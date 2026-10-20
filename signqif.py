#!/usr/bin/env python3
"""QIF Digital Signature Tool

This program creates an XML digital signature for input QIF Document using
input file and external QIF documents as references.

External libraries lxml and cryptography are required.

Usage examples:
    # Create a self-signed certificate for testing
    openssl req -x509 -newkey rsa:2048 -noenc -keyout key.pem -out cert.cer
    
    # Sign a QIF document
    python signqif.py -v -key 'key.pem' -cert 'cert.cer' 'Exploded_Results1.QIF'
    
    # Validate the signature
    xmlsec1 --verify --trusted-pem cert.cer Exploded_Results1-signed.QIF
"""

import argparse
import base64
import copy
import getpass
import hashlib
import logging
import os
import sys
from typing import Optional, Tuple, Union, cast
from urllib.parse import urlparse
from urllib.request import url2pathname

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from lxml import etree
from lxml.etree import _Element, _ElementTree

# Environment variable holding the private key password, for unattended signing
KEY_PASSWORD_ENV = 'QIF_KEY_PASSWORD'

# Password prompts allowed before giving up
PASSWORD_ATTEMPTS = 3


def setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity level."""
    logging.basicConfig()
    if verbose:
        logging.getLogger().setLevel(logging.INFO)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Program creates an XML digital signature for input QIF '
                   'Document using input file and external QIF documents as references.'
    )
    parser.add_argument(
        'qifFile',
        help='QIF file to be signed'
    )
    parser.add_argument(
        '-key', 
        help='Private key in PEM format', 
        type=argparse.FileType('rb'), 
        required=True
    )
    parser.add_argument(
        '-keypass',
        help=argparse.SUPPRESS  # Removed, kept only to explain the removal
    )
    parser.add_argument(
        '-cert', 
        help='x509 cert in PEM format', 
        type=argparse.FileType('rb'), 
        required=True
    )
    parser.add_argument(
        '-v', 
        help='Verbose', 
        action='store_true'
    )
    parser.add_argument(
        '--pretty-print',
        help='Format output XML with indentation for readability',
        action='store_true'
    )
    args = parser.parse_args()
    if args.keypass is not None:
        parser.error(f'-keypass has been removed because passwords on the command line are visible to other '
                     f'users and saved in shell history. You will be prompted for the password, or set the '
                     f'{KEY_PASSWORD_ENV} environment variable for unattended signing.')
    return args


def load_qif_document(qif_path: str) -> _ElementTree:
    """Load and validate QIF document."""
    # libxml2 treats '-' as standard input, unsupported since the output file name and
    # external reference locations are derived from the input path
    if qif_path == '-':
        raise SystemExit('Reading the QIF file from standard input is not supported, give a file path.')
    
    # Parsed from the file so the XML declaration determines the encoding
    try:
        tree = etree.parse(qif_path, parser=etree.XMLParser())
    except etree.XMLSyntaxError as e:
        raise SystemExit(f'Unable to parse XML from QIF file: {e}')
    except OSError as e:
        raise SystemExit(f'Unable to read QIF file: {e}')
    
    # Confirm document is a QIF Document
    qif_root = tree.getroot()
    if qif_root.tag != '{http://qifstandards.org/xsd/qif3}QIFDocument':
        raise SystemExit('QIF file does not contain QIFDocument as its root element.')
    
    # Check for existing signature and remove if found
    # This simplifies the program and preemptively applies the enveloped signature transformation
    sig_element = tree.find("./{http://www.w3.org/2000/09/xmldsig#}Signature")
    if sig_element is not None:
        parent = sig_element.getparent()
        if parent is not None:
            parent.remove(sig_element)
            logging.warning('QIFDocument Signature found in input file. Existing signature data being dropped.')
    
    return tree


def load_certificate(cert_file) -> Tuple[x509.Certificate, Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey], str, str]:
    """Load x509 certificate and determine signature algorithm."""
    try:
        cert = x509.load_pem_x509_certificate(cert_file.read())
    except ValueError as e:
        raise SystemExit(f'Unable to load x509 certificate, PEM format is required: {e}')
    
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        sign_algorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        sign_method = 'rsa'
        logging.info('RSA cryptosystem detected in certification.')
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        sign_algorithm = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256'
        sign_method = 'ecdsa'
        logging.info('ECDSA cryptosystem detected in certification.')
    else:
        raise SystemExit('Certificate does not contain a recognized cryptosystem, '
                        'allowable types are RSA and ECDSA.')
    
    return cert, public_key, sign_algorithm, sign_method


def can_prompt() -> bool:
    """Return True if a person is at a terminal to type a password."""
    if sys.stdin is None or not sys.stdin.isatty():
        return False
    if sys.platform == 'win32':
        # NUL also reports as a tty on Windows, only a real console has a console mode
        import ctypes
        import msvcrt
        mode = ctypes.c_uint32()
        handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        return bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)))
    return True


def prompt_password(key_name: str) -> str:
    """Prompt for a private key password without echoing it."""
    try:
        return getpass.getpass(f'Password for {key_name}: ')
    except (KeyboardInterrupt, EOFError):
        raise SystemExit('Cancelled.')


def decrypt_private_key(key_data: bytes, password: str) -> Optional[PrivateKeyTypes]:
    """Return the decrypted private key, or None if the password is incorrect."""
    try:
        return serialization.load_pem_private_key(key_data, password=password.encode('utf-8'))
    except (ValueError, TypeError):  # Key is known to be encrypted, so failing to decrypt (or an empty password) means a wrong password
        return None
    except UnsupportedAlgorithm as e:
        raise SystemExit(f'Unable to load private key: {e}')


def load_encrypted_private_key(key_data: bytes, key_name: str) -> PrivateKeyTypes:
    """Load an encrypted private key using the password from the environment, or by prompting for it."""
    env_password = os.environ.get(KEY_PASSWORD_ENV)
    if env_password:
        private_key = decrypt_private_key(key_data, env_password)
        if private_key is None:
            raise SystemExit(f'Incorrect password for {key_name} in the {KEY_PASSWORD_ENV} environment variable.')
        return private_key
    
    if not can_prompt():
        raise SystemExit(f'Private key is encrypted. Run interactively to be prompted for the password, '
                         f'or set the {KEY_PASSWORD_ENV} environment variable.')
    for attempt in range(PASSWORD_ATTEMPTS):
        if attempt > 0:
            print('Incorrect password, try again.', file=sys.stderr)
        private_key = decrypt_private_key(key_data, prompt_password(key_name))
        if private_key is not None:
            return private_key
    raise SystemExit(f'Incorrect password for {key_name}.')


def load_private_key(key_file, sign_method: str) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
    """Load and validate private key."""
    key_data = key_file.read()
    try:
        private_key = serialization.load_pem_private_key(key_data, password=None)
    except TypeError:  # Key is encrypted, the password is only requested when needed
        private_key = load_encrypted_private_key(key_data, key_file.name)
    except (ValueError, UnsupportedAlgorithm) as e:  # Not PEM, or unsupported key type
        raise SystemExit(f'Unable to load private key, PEM format is required: {e}')
    
    if isinstance(private_key, rsa.RSAPrivateKey) and sign_method == 'rsa':
        logging.info('RSA cryptosystem detected in private key.')
    elif isinstance(private_key, ec.EllipticCurvePrivateKey) and sign_method == 'ecdsa':
        logging.info('ECDSA cryptosystem detected in private key.')
    else:
        raise SystemExit('Private key does not contain a recognized cryptosystem or '
                        'does not match certificate cryptosystem, allowable types are RSA and ECDSA.')
    
    return private_key


def digest_document(document: _ElementTree, uri: str) -> str:
    """Return the base64 SHA256 digest of the c14n form of a document."""
    doc_string = etree.tostring(document, method="c14n", with_comments=False)
    doc_digest = base64.b64encode(hashlib.sha256(doc_string).digest()).decode('ascii')
    logging.info(f"{uri} digested to {doc_digest}")
    return doc_digest


def apply_enveloped_transform(tree: _ElementTree, signature: _Element) -> _ElementTree:
    """Return a copy of the QIF Document with the Signature element removed."""
    sig_index = tree.getroot().index(signature)
    document = copy.deepcopy(tree)
    parent = document.getroot()
    sig_element = parent[sig_index]
    
    # Enveloped signature transformation removes only the element, whitespace text around it is kept
    previous = sig_element.getprevious()
    if previous is not None:
        previous.tail = (previous.tail or '') + (sig_element.tail or '')
    else:
        parent.text = (parent.text or '') + (sig_element.tail or '')
    parent.remove(sig_element)
    
    return document


def resolve_reference_path(uri: str, base_dir: str) -> str:
    """Resolve an external QIF document URI to a local path, relative to the signed QIF document."""
    parsed = urlparse(uri)
    if parsed.scheme == 'file':
        if parsed.netloc not in ('', 'localhost'):
            raise SystemExit(f'External QIF document {uri} is on a remote host, only local files are supported.')
        return url2pathname(parsed.path)
    if len(parsed.scheme) == 1:  # Windows drive letter, an absolute path rather than a URI scheme
        return uri
    if parsed.scheme:
        raise SystemExit(f'External QIF document {uri} is not a local file, only relative paths and file URIs are supported.')
    
    # Verifiers resolve relative URIs against the signed document's location, not the working directory
    return os.path.join(base_dir, url2pathname(uri))


def build_reference(uri: str, base_dir: str) -> _Element:
    """Create a Reference element for the given URI, digested now if external."""
    base_reference = etree.Element('Reference', attrib={"URI": uri})
    
    # Add transforms
    br_transforms = etree.SubElement(base_reference, 'Transforms')
    if uri == "":  # Add enveloped signature transformation to QIF Document being signed
        etree.SubElement(
            br_transforms,
            'Transform',
            attrib={"Algorithm": "http://www.w3.org/2000/09/xmldsig#enveloped-signature"}
        )
        # Applied by apply_enveloped_transform when the QIF Document is digested
    
    # All references assumed to be XML, all get c14n transformation
    etree.SubElement(
        br_transforms,
        'Transform',
        attrib={"Algorithm": "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"}
    )
    
    # Use SHA256 as the digest method, SHA1 is not recommended
    etree.SubElement(
        base_reference,
        'DigestMethod',
        attrib={"Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"}
    )
    
    br_digest_value = etree.SubElement(base_reference, 'DigestValue')
    if uri != "":  # External QIF Document
        path = resolve_reference_path(uri, base_dir)
        try:
            document = etree.parse(path, parser=etree.XMLParser())
        except etree.XMLSyntaxError as e:
            raise SystemExit(f'Unable to parse XML from external QIF document {uri}: {e}')
        except OSError as e:
            raise SystemExit(f'Unable to read external QIF document {uri} ({path}): {e}')
        br_digest_value.text = digest_document(document, uri)
    # Loaded QIF Document is digested after the signature is placed and formatted
    
    return base_reference


def create_signature_element(tree: _ElementTree, sign_algorithm: str, base_dir: str) -> Tuple[_Element, _Element]:
    """Create the main Signature element with SignedInfo."""
    # Signature element contains all signature data per xmldsig
    signature = etree.Element('Signature', nsmap={None: "http://www.w3.org/2000/09/xmldsig#"})
    
    # SignedInfo contains digested values for referenced documents and how information will be signed
    signed_info = etree.SubElement(signature, 'SignedInfo')
    
    # Canonicalization method is applied to SignedInfo
    # As of lxml 4.8.0 only c14n 1.0 and c14n 1.0 exclusive can be applied
    etree.SubElement(
        signed_info,
        'CanonicalizationMethod',
        attrib={"Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"}
    )
    
    # Signature method is applied to the digested SignedInfo, method is extracted from the certification
    etree.SubElement(
        signed_info,
        'SignatureMethod',
        attrib={"Algorithm": sign_algorithm}
    )
    
    # Create digested reference for QIF Document
    signed_info.append(build_reference("", base_dir))
    
    # Loop through external documents, create digested reference if URI element exists
    ext_qif_docs = tree.iterfind(".//{http://qifstandards.org/xsd/qif3}ExternalQIFDocument")
    for ext_qif_doc in ext_qif_docs:
        qpid = ext_qif_doc.findtext(".//{http://qifstandards.org/xsd/qif3}QPId")
        uri = ext_qif_doc.findtext(".//{http://qifstandards.org/xsd/qif3}URI")
        if uri is not None:
            signed_info.append(build_reference(uri, base_dir))
            logging.info(f'Added signature reference for external QIF document {qpid}')
        else:
            logging.warning(f'External QIF Document {qpid} has no URI, skipped')
    
    return signature, signed_info


def sign_document(signed_info: _Element, private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey], sign_method: str) -> bytes:
    """Create the signature value for the SignedInfo."""
    sign_info_c14n = etree.tostring(signed_info, method="c14n", with_comments=False, exclusive=True)
    
    if sign_method == 'rsa':
        rsa_key = cast(rsa.RSAPrivateKey, private_key)
        sig_val = rsa_key.sign(
            sign_info_c14n,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    else:  # assumed to be ecdsa, no padding argument
        ec_key = cast(ec.EllipticCurvePrivateKey, private_key)
        der_sig = ec_key.sign(
            sign_info_c14n,
            ec.ECDSA(hashes.SHA256())
        )
        # XML Signature requires the raw r || s form (RFC 4050), cryptography produces DER
        r, s = decode_dss_signature(der_sig)
        size = (ec_key.curve.key_size + 7) // 8
        sig_val = r.to_bytes(size, 'big') + s.to_bytes(size, 'big')
    
    return sig_val


def add_key_info(signature: _Element, cert: x509.Certificate) -> None:
    """Add KeyInfo with X509 certificate to the signature element."""
    key_info = etree.SubElement(signature, 'KeyInfo')
    x509_data = etree.SubElement(key_info, 'X509Data')
    x509_cert = etree.SubElement(x509_data, 'X509Certificate')
    x509_cert.text = base64.b64encode(cert.public_bytes(serialization.Encoding.DER))


def ecdsa_raw_to_der(sig_val: bytes) -> bytes:
    """Convert an XML Signature ECDSA value (raw r || s) to the DER form cryptography expects."""
    size = len(sig_val) // 2
    return encode_dss_signature(
        int.from_bytes(sig_val[:size], 'big'),
        int.from_bytes(sig_val[size:], 'big')
    )


def verify_signature(public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey], sig_val: bytes, signed_info: _Element, sign_method: str) -> None:
    """Verify that the public key can validate the signature value."""
    sign_info_c14n = etree.tostring(signed_info, method="c14n", with_comments=False, exclusive=True)
    
    try:
        if sign_method == 'rsa':
            rsa_pub_key = cast(rsa.RSAPublicKey, public_key)
            rsa_pub_key.verify(
                sig_val,
                sign_info_c14n,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        else:  # assumed to be ecdsa, no padding argument
            ec_pub_key = cast(ec.EllipticCurvePublicKey, public_key)
            ec_pub_key.verify(
                ecdsa_raw_to_der(sig_val),
                sign_info_c14n,
                ec.ECDSA(hashes.SHA256())
            )
    except InvalidSignature:
        raise SystemExit('Unable to validate signature with public key, '
                        'possible mismatch between private key and certificate')


def save_signed_document(tree: _ElementTree, original_filename: str, pretty_print: bool = False) -> str:
    """Save the signed QIF document with '-signed' appended to filename."""
    type_loc = original_filename.rfind('.')
    if type_loc == -1:
        type_loc = len(original_filename)
    
    file_name = original_filename[:type_loc] + '-signed' + original_filename[type_loc:]
    
    # Formatting has already been applied before signature computation
    # Just save the document as-is to preserve signature validity
    try:
        with open(file_name, 'wb') as f:
            tree.write(f, encoding='utf-8', xml_declaration=True)
    except OSError as e:
        raise SystemExit(f'Unable to write signed QIF document {file_name}: {e}')
    
    format_type = "pretty-printed" if pretty_print else "formatted with newlines, no indentation"
    logging.info(f'Signed QIF document written to file {file_name} ({format_type})')
    
    return file_name


def main():
    """Main execution function."""
    args = parse_arguments()
    setup_logging(args.v)
    
    # Load QIF Document
    tree = load_qif_document(args.qifFile)
    
    # Load Certificate
    cert, public_key, sign_algorithm, sign_method = load_certificate(args.cert)
    
    # Load Private Key
    private_key = load_private_key(args.key, sign_method)
    
    # Create Signature Element, SignatureValue is filled in once SignedInfo is signed
    base_dir = os.path.dirname(os.path.abspath(args.qifFile))
    signature, signed_info = create_signature_element(tree, sign_algorithm, base_dir)
    signature_value = etree.SubElement(signature, 'SignatureValue')
    add_key_info(signature, cert)
    
    # Add signature block to QIF Document tree
    qif_root = tree.getroot()
    qif_root.append(signature)
    
    # Apply user's desired formatting to the whole document, signature block included, BEFORE
    # computing digest and signature so the written whitespace matches what was signed.
    # indent only replaces whitespace-only text between elements, element values are left untouched
    pretty_print_flag = getattr(args, 'pretty_print', False)
    if pretty_print_flag:
        etree.indent(tree, space="  ")
    else:
        # Newlines with zero indentation
        etree.indent(tree, space="")
    
    # Digest the QIF Document now that its final layout is known
    doc_digest_value = signed_info.find('Reference[@URI=""]/DigestValue')
    doc_digest_value.text = digest_document(apply_enveloped_transform(tree, signature), "")
    
    # Sign the document
    sig_val = sign_document(signed_info, private_key, sign_method)
    signature_value.text = base64.b64encode(sig_val)
    
    # Verify signature
    verify_signature(public_key, sig_val, signed_info, sign_method)
    
    # Save signed document
    save_signed_document(tree, args.qifFile, getattr(args, 'pretty_print', False))


if __name__ == "__main__":
    main()