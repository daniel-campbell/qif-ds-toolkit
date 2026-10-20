#!/usr/bin/env python3
"""QIF Digital Signature Verification Tool

This program verifies the XML digital signature of a QIF Document, including
the digests of any external QIF documents it references.

External libraries lxml and cryptography are required.

Usage examples:
    # Check that the document has not changed since it was signed
    python verifyqif.py Exploded_Results1-signed.QIF
    
    # Also require that it was signed with a certificate you trust
    python verifyqif.py -cert trusted.cer Exploded_Results1-signed.QIF
"""

import argparse
import base64
import copy
import hashlib
import io
import logging
import os
from datetime import datetime, timezone
from typing import Optional, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from lxml import etree
from lxml.etree import _Element, _ElementTree

from signqif import apply_enveloped_transform, ecdsa_raw_to_der, resolve_reference_path, setup_logging

DS = '{http://www.w3.org/2000/09/xmldsig#}'
EXC_C14N = '{http://www.w3.org/2001/10/xml-exc-c14n#}'

ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'

# Canonicalization algorithms, (exclusive, with comments)
C14N_METHODS = {
    'http://www.w3.org/TR/2001/REC-xml-c14n-20010315': (False, False),
    'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments': (False, True),
    'http://www.w3.org/2001/10/xml-exc-c14n#': (True, False),
    'http://www.w3.org/2001/10/xml-exc-c14n#WithComments': (True, True),
}

# Digest algorithms, hashlib name
DIGEST_METHODS = {
    'http://www.w3.org/2001/04/xmlenc#sha256': 'sha256',
    'http://www.w3.org/2001/04/xmldsig-more#sha384': 'sha384',
    'http://www.w3.org/2001/04/xmlenc#sha512': 'sha512',
}

# Signature algorithms, (cryptosystem, hash)
SIGNATURE_METHODS = {
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': ('rsa', hashes.SHA256),
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384': ('rsa', hashes.SHA384),
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': ('rsa', hashes.SHA512),
    'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256': ('ecdsa', hashes.SHA256),
    'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384': ('ecdsa', hashes.SHA384),
    'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512': ('ecdsa', hashes.SHA512),
}


class ReferenceProblem(Exception):
    """A Reference that could not be checked, reported as a failure rather than stopping verification."""


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Program verifies the XML digital signature of a QIF Document, '
                   'including external QIF documents it references.'
    )
    parser.add_argument(
        'qifFile',
        help='Signed QIF file to be verified'
    )
    parser.add_argument(
        '-cert',
        help='x509 cert in PEM format that the document must be signed with. '
             'Without it, the certificate embedded in the document is used.',
        type=argparse.FileType('rb')
    )
    parser.add_argument(
        '-v',
        help='Verbose',
        action='store_true'
    )
    return parser.parse_args()


def load_signed_document(qif_path: str) -> Tuple[_ElementTree, _Element]:
    """Load a signed QIF document and find its Signature element."""
    if qif_path == '-':
        raise SystemExit('Reading the QIF file from standard input is not supported, give a file path.')
    
    try:
        tree = etree.parse(qif_path, parser=etree.XMLParser())
    except etree.XMLSyntaxError as e:
        raise SystemExit(f'Unable to parse XML from QIF file: {e}')
    except OSError as e:
        raise SystemExit(f'Unable to read QIF file: {e}')
    
    signature = tree.getroot().find(f'{DS}Signature')
    if signature is None:
        raise SystemExit('QIF file is not signed, no Signature element found in QIFDocument.')
    
    return tree, signature


def find_required(parent: _Element, path: str) -> _Element:
    """Find a required element of the Signature, exiting if the Signature is malformed."""
    element = parent.find(path)
    if element is None:
        raise SystemExit(f'Signature is malformed, {path.replace(DS, "")} not found.')
    return element


def canonicalize(node, method: _Element, allow_comments: bool = True) -> bytes:
    """Canonicalize a document or element with the algorithm named by a method element."""
    algorithm = method.get('Algorithm')
    if algorithm not in C14N_METHODS:
        raise ReferenceProblem(f'unsupported canonicalization algorithm {algorithm}')
    exclusive, with_comments = C14N_METHODS[algorithm]
    
    prefixes = None
    if exclusive:
        inclusive_namespaces = method.find(f'{EXC_C14N}InclusiveNamespaces')
        if inclusive_namespaces is not None:
            prefixes = inclusive_namespaces.get('PrefixList', '').split()
    elif isinstance(node, _Element):
        node = standalone_copy(node)
    
    return etree.tostring(node, method='c14n', exclusive=exclusive,
                          with_comments=with_comments and allow_comments, inclusive_ns_prefixes=prefixes)


def standalone_copy(element: _Element) -> _Element:
    """Copy an element into its own document for inclusive c14n of a subtree.
    
    lxml's inclusive c14n of an element inside a larger document emits spurious xmlns="" on
    descendants. Inclusive c14n of a subtree must render every in-scope namespace and inherited
    xml:* attribute on the top element, so the copy declares them there explicitly.
    """
    copy_root = etree.Element(element.tag, attrib=dict(element.attrib), nsmap=element.nsmap)
    for ancestor in element.iterancestors():  # Nearest ancestor first, so its value wins
        for name, value in ancestor.attrib.items():
            if name.startswith('{http://www.w3.org/XML/1998/namespace}') and name not in copy_root.attrib:
                copy_root.set(name, value)
    copy_root.text = element.text
    for child in element:
        copy_root.append(copy.deepcopy(child))
    return copy_root


def dereference(reference: _Element, tree: _ElementTree, signature: _Element, base_dir: str) -> bytes:
    """Return the bytes a Reference digests, after applying its transforms."""
    uri = reference.get('URI')
    if uri is None or uri.startswith('#'):
        raise ReferenceProblem('only whole-document references are supported')
    
    if uri == '':  # This document, comments are excluded per XML Signature
        data = tree
    else:  # External QIF Document, its bytes until a transform needs XML
        path = resolve_reference_path(uri, base_dir)
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except OSError as e:
            raise ReferenceProblem(f'unable to read {path}: {e.strerror}')
    
    for transform in reference.findall(f'{DS}Transforms/{DS}Transform'):
        algorithm = transform.get('Algorithm')
        if algorithm == ENVELOPED_SIGNATURE:
            if uri != '' or isinstance(data, bytes):
                raise ReferenceProblem('enveloped signature transform only applies to the signed document itself')
            data = apply_enveloped_transform(data, signature)
        elif algorithm in C14N_METHODS:
            if isinstance(data, bytes):
                try:
                    data = etree.parse(io.BytesIO(data), parser=etree.XMLParser())
                except etree.XMLSyntaxError as e:
                    raise ReferenceProblem(f'unable to parse XML: {e}')
            data = canonicalize(data, transform, allow_comments=(uri != ''))
        else:
            raise ReferenceProblem(f'unsupported transform {algorithm}')
    
    # XML left after the transforms is converted to bytes with inclusive c14n, per XML Signature
    if not isinstance(data, bytes):
        data = etree.tostring(data, method='c14n', exclusive=False, with_comments=False)
    return data


def check_reference(reference: _Element, tree: _ElementTree, signature: _Element, base_dir: str) -> Optional[str]:
    """Check a Reference digest, returning None if it matches or the reason it does not."""
    try:
        digest_method = find_required(reference, f'{DS}DigestMethod').get('Algorithm')
        if digest_method not in DIGEST_METHODS:
            raise ReferenceProblem(f'unsupported digest algorithm {digest_method}')
        data = dereference(reference, tree, signature, base_dir)
    except ReferenceProblem as e:
        return str(e)
    
    digest = hashlib.new(DIGEST_METHODS[digest_method], data).digest()
    logging.info(f'{reference.get("URI")} digested to {base64.b64encode(digest).decode("ascii")}')
    expected = base64.b64decode(reference.findtext(f'{DS}DigestValue') or '')
    if digest != expected:
        return 'digest does not match, the document has changed since it was signed'
    return None


def load_embedded_certificates(signature: _Element) -> list:
    """Load the x509 certificates embedded in the Signature KeyInfo."""
    certs = []
    for cert_text in signature.iterfind(f'{DS}KeyInfo/{DS}X509Data/{DS}X509Certificate'):
        try:
            certs.append(x509.load_der_x509_certificate(base64.b64decode(cert_text.text or '')))
        except ValueError as e:
            logging.warning(f'Skipping unreadable embedded certificate: {e}')
    return certs


def signature_matches(cert: x509.Certificate, signed_bytes: bytes, sig_val: bytes, signature_method: str) -> bool:
    """Return True if the certificate's public key validates the signature value."""
    cryptosystem, hash_type = SIGNATURE_METHODS[signature_method]
    public_key = cert.public_key()
    try:
        if cryptosystem == 'rsa' and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(sig_val, signed_bytes, padding.PKCS1v15(), hash_type())
        elif cryptosystem == 'ecdsa' and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(ecdsa_raw_to_der(sig_val), signed_bytes, ec.ECDSA(hash_type()))
        else:  # Key type does not match the signature algorithm
            return False
    except InvalidSignature:
        return False
    return True


def describe_certificate(cert: x509.Certificate) -> None:
    """Print who a certificate identifies and whether it is currently within its validity period."""
    fingerprint = cert.fingerprint(hashes.SHA256()).hex(':').upper()
    print(f'  Subject:     {cert.subject.rfc4514_string()}')
    print(f'  Issuer:      {cert.issuer.rfc4514_string()}')
    print(f'  Valid:       {cert.not_valid_before_utc:%Y-%m-%d} to {cert.not_valid_after_utc:%Y-%m-%d}')
    print(f'  Fingerprint: SHA256 {fingerprint}')
    
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        print('  Note: the certificate is outside its validity period today. The document does not record '
              'when it was signed, so whether this matters depends on your policy.')


def main():
    """Main execution function."""
    args = parse_arguments()
    setup_logging(args.v)
    
    tree, signature = load_signed_document(args.qifFile)
    base_dir = os.path.dirname(os.path.abspath(args.qifFile))
    valid = True
    
    # Check the digest of every referenced document
    signed_info = find_required(signature, f'{DS}SignedInfo')
    for reference in signed_info.iterfind(f'{DS}Reference'):
        uri = reference.get('URI')
        label = 'this document' if uri == '' else uri
        problem = check_reference(reference, tree, signature, base_dir)
        if problem is None:
            print(f'Reference {label}: OK')
        else:
            print(f'Reference {label}: FAILED, {problem}')
            valid = False
    
    # Check the signature over SignedInfo
    signature_method = find_required(signed_info, f'{DS}SignatureMethod').get('Algorithm')
    if signature_method not in SIGNATURE_METHODS:
        raise SystemExit(f'Unsupported signature algorithm {signature_method}.')
    try:
        signed_bytes = canonicalize(signed_info, find_required(signed_info, f'{DS}CanonicalizationMethod'))
    except ReferenceProblem as e:
        raise SystemExit(f'Unable to check signature, {e}.')
    sig_val = base64.b64decode(find_required(signature, f'{DS}SignatureValue').text or '')
    
    if args.cert:
        try:
            candidates = [x509.load_pem_x509_certificate(args.cert.read())]
        except ValueError as e:
            raise SystemExit(f'Unable to load x509 certificate, PEM format is required: {e}')
    else:
        candidates = load_embedded_certificates(signature)
        if not candidates:
            raise SystemExit('No certificate is embedded in the QIF file, use -cert to give the signer certificate.')
    
    signer_cert = next((c for c in candidates if signature_matches(c, signed_bytes, sig_val, signature_method)), None)
    if signer_cert is None:
        source = 'the certificate given by -cert' if args.cert else 'the certificate embedded in the file'
        print(f'Signature: FAILED, not signed with {source}')
        valid = False
    else:
        print('Signature: OK')
        print('Signed with certificate:')
        describe_certificate(signer_cert)
        if args.cert:
            print('  Checked against the certificate given by -cert.')
        else:
            print('  Checked against the certificate embedded in the file. This shows the document has not '
                  'changed since it was signed, not who signed it. Use -cert to require a certificate you trust.')
    
    print('Result: VALID' if valid else 'Result: INVALID')
    raise SystemExit(0 if valid else 1)


if __name__ == "__main__":
    main()
