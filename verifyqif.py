#!/usr/bin/env python3
"""QIF Digital Signature Verification Tool

This program verifies the XML digital signature of each input QIF Document,
including the digests of any external QIF documents it references.

External libraries lxml and cryptography are required.

Usage examples:
    # Check that the document has not changed since it was signed
    python verifyqif.py Exploded_Results1-signed.QIF
    
    # Also require that it was signed with a certificate you trust
    python verifyqif.py -cert trusted.cer Exploded_Results1-signed.QIF
    
    # Check a batch and print a report a script can read
    python verifyqif.py --json signed/*.qif
"""

import argparse
import base64
import copy
import hashlib
import io
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from lxml import etree
from lxml.etree import _Element, _ElementTree

from signqif import (apply_enveloped_transform, certificate_fingerprint, certificate_validity_note,
                     ecdsa_raw_to_der, resolve_reference_path, setup_logging)

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
        description='Program verifies the XML digital signature of each input QIF Document, '
                   'including external QIF documents it references.'
    )
    parser.add_argument(
        'qifFiles',
        nargs='+',
        metavar='qifFile',
        help='Signed QIF file(s) to be verified'
    )
    parser.add_argument(
        '-cert',
        help='x509 cert in PEM format that the documents must be signed with. A file holding '
             'several certificates, such as a chain, is accepted. Without it, the certificate '
             'embedded in each document is used.',
        type=argparse.FileType('rb')
    )
    parser.add_argument(
        '--json',
        help='Print a machine-readable JSON report instead of the text summary',
        action='store_true'
    )
    parser.add_argument(
        '-v',
        help='Verbose',
        action='store_true'
    )
    return parser.parse_args()


def load_trusted_certificates(cert_file) -> List[x509.Certificate]:
    """Load every certificate of the file given by -cert, so a chain can be given as one file."""
    try:
        certificates = x509.load_pem_x509_certificates(cert_file.read())
    except ValueError as e:
        raise SystemExit(f'Unable to load x509 certificate, PEM format is required: {e}')
    
    if not certificates:
        raise SystemExit(f'No certificate found in {cert_file.name}, PEM format is required.')
    return certificates


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


def load_embedded_certificates(signature: _Element) -> List[x509.Certificate]:
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


def certificate_details(cert: x509.Certificate, source: str) -> Dict[str, Any]:
    """Describe who a certificate identifies and whether it is currently within its validity period."""
    return {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'not_valid_before': f'{cert.not_valid_before_utc:%Y-%m-%d}',
        'not_valid_after': f'{cert.not_valid_after_utc:%Y-%m-%d}',
        'within_validity_period': certificate_validity_note(cert) is None,
        'sha256_fingerprint': certificate_fingerprint(cert),
        'source': source,
    }


def check_document(qif_path: str, trusted_certificates: Optional[List[x509.Certificate]]) -> Dict[str, Any]:
    """Verify one signed document and return what was found, without printing anything."""
    tree, signature = load_signed_document(qif_path)
    base_dir = os.path.dirname(os.path.abspath(qif_path))
    report: Dict[str, Any] = {
        'file': qif_path,
        'references': [],
        'signature': {'status': 'not checked', 'reason': None},
        'certificate': None,
        'result': 'invalid',
    }
    references = report['references']
    
    # Check the digest of every referenced document
    signed_info = find_required(signature, f'{DS}SignedInfo')
    for reference in signed_info.iterfind(f'{DS}Reference'):
        uri = reference.get('URI')
        problem = check_reference(reference, tree, signature, base_dir)
        references.append({'uri': uri, 'status': 'ok' if problem is None else 'failed', 'problem': problem})
    
    # Check the signature over SignedInfo
    signature_method = find_required(signed_info, f'{DS}SignatureMethod').get('Algorithm')
    if signature_method not in SIGNATURE_METHODS:
        raise SystemExit(f'Unsupported signature algorithm {signature_method}.')
    try:
        signed_bytes = canonicalize(signed_info, find_required(signed_info, f'{DS}CanonicalizationMethod'))
    except ReferenceProblem as e:
        raise SystemExit(f'Unable to check signature, {e}.')
    sig_val = base64.b64decode(find_required(signature, f'{DS}SignatureValue').text or '')
    
    if trusted_certificates:
        candidates = trusted_certificates
    else:
        candidates = load_embedded_certificates(signature)
        if not candidates:
            raise SystemExit('No certificate is embedded in the QIF file, use -cert to give the signer certificate.')
    
    signer_cert = next((c for c in candidates if signature_matches(c, signed_bytes, sig_val, signature_method)), None)
    if signer_cert is None:
        source = 'the certificate given by -cert' if trusted_certificates else 'the certificate embedded in the file'
        report['signature'] = {'status': 'failed', 'reason': f'not signed with {source}'}
    else:
        report['signature'] = {'status': 'ok', 'reason': None}
        report['certificate'] = certificate_details(
            signer_cert, 'argument' if trusted_certificates else 'embedded')
    
    references_ok = all(reference['status'] == 'ok' for reference in references)
    report['result'] = 'valid' if references_ok and report['signature']['status'] == 'ok' else 'invalid'
    return report


def error_report(qif_path: str, message: str) -> Dict[str, Any]:
    """Report a document that could not be checked at all."""
    return {
        'file': qif_path,
        'error': message,
        'references': [],
        'signature': {'status': 'not checked', 'reason': None},
        'certificate': None,
        'result': 'invalid',
    }


def print_certificate(details: Dict[str, Any]) -> None:
    """Print the certificate block of a text report."""
    print(f'  Subject:     {details["subject"]}')
    print(f'  Issuer:      {details["issuer"]}')
    print(f'  Valid:       {details["not_valid_before"]} to {details["not_valid_after"]}')
    print(f'  Fingerprint: SHA256 {details["sha256_fingerprint"]}')
    if not details['within_validity_period']:
        print('  Note: the certificate is outside its validity period today. The document does not record '
              'when it was signed, so whether this matters depends on your policy.')
    if details['source'] == 'argument':
        print('  Checked against the certificate given by -cert.')
    else:
        print('  Checked against the certificate embedded in the file. This shows the document has not '
              'changed since it was signed, not who signed it. Use -cert to require a certificate you trust.')


def print_report(report: Dict[str, Any], label_file: bool = False) -> None:
    """Print one document's verification result in the text format."""
    if 'error' in report:
        label = f'{report["file"]}: ' if label_file else ''
        print(f'{label}{report["error"]}', file=sys.stderr)
        return
    
    for reference in report['references']:
        label = 'this document' if reference['uri'] == '' else reference['uri']
        if reference['status'] == 'ok':
            print(f'Reference {label}: OK')
        else:
            print(f'Reference {label}: FAILED, {reference["problem"]}')
    
    if report['signature']['status'] == 'ok':
        print('Signature: OK')
        print('Signed with certificate:')
        print_certificate(report['certificate'])
    else:
        print(f'Signature: FAILED, {report["signature"]["reason"]}')
    print('Result: VALID' if report['result'] == 'valid' else 'Result: INVALID')


def main() -> int:
    """Main execution function."""
    args = parse_arguments()
    setup_logging(args.v)
    
    trusted_certificates = load_trusted_certificates(args.cert) if args.cert else None
    reports = []
    for qif_path in args.qifFiles:
        try:
            reports.append(check_document(qif_path, trusted_certificates))
        except SystemExit as e:
            # One unusable document must not stop a batch, it is reported as invalid
            message = e.code if isinstance(e.code, str) else 'Unable to verify the document.'
            reports.append(error_report(qif_path, message))
    
    valid_count = sum(1 for report in reports if report['result'] == 'valid')
    invalid_count = len(reports) - valid_count
    batch = len(reports) > 1
    
    if args.json:
        print(json.dumps({
            'files': reports,
            'documents': len(reports),
            'valid': valid_count,
            'invalid': invalid_count,
            'result': 'valid' if invalid_count == 0 else 'invalid',
        }, indent=2))
    else:
        for index, report in enumerate(reports):
            if batch:
                if index:
                    print()
                print(f'== {report["file"]} ==')
            print_report(report, label_file=batch)
        if batch:
            print()
            print(f'{valid_count} of {len(reports)} documents valid.')
    
    return 0 if invalid_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
