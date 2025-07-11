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
    xmlsec --verify --trusted-pem cert.cer Exploded_Results1-signed.QIF
"""

import argparse
import base64
import hashlib
import logging
from typing import Optional, Tuple, Union, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from lxml import etree
from lxml.etree import _Element, _ElementTree


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
        help='QIF file to be signed', 
        type=argparse.FileType('r', encoding='UTF-8')
    )
    parser.add_argument(
        '-key', 
        help='Private key in PEM format', 
        type=argparse.FileType('rb'), 
        required=True
    )
    parser.add_argument(
        '-keypass', 
        help='Password for private key'
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
    return parser.parse_args()


def load_qif_document(qif_file) -> _ElementTree:
    """Load and validate QIF document."""
    try:
        tree = etree.parse(qif_file, parser=etree.XMLParser())
    except Exception:
        raise SystemExit('Unable to parse XML from QIF file.')
    
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
    cert = x509.load_pem_x509_certificate(cert_file.read())
    
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


def load_private_key(key_file, password: Optional[str], sign_method: str) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
    """Load and validate private key."""
    password_bytes = password.encode('utf-8') if password else None
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=password_bytes,
    )
    
    if isinstance(private_key, rsa.RSAPrivateKey) and sign_method == 'rsa':
        logging.info('RSA cryptosystem detected in private key.')
    elif isinstance(private_key, ec.EllipticCurvePrivateKey) and sign_method == 'ecdsa':
        logging.info('ECDSA cryptosystem detected in private key.')
    else:
        raise SystemExit('Private key does not contain a recognized cryptosystem or '
                        'does not match certificate cryptosystem, allowable types are RSA and ECDSA.')
    
    return private_key


def build_reference(uri: str, tree: _ElementTree) -> _Element:
    """Create a completed Reference element for the given URI."""
    base_reference = etree.Element('Reference', attrib={"URI": uri})
    
    # Determine document source
    if uri == "":  # Loaded QIF Document
        document = tree
    else:  # External QIF Document
        document = etree.parse(uri, parser=etree.XMLParser())
    
    # Add transforms
    br_transforms = etree.SubElement(base_reference, 'Transforms')
    if uri == "":  # Add enveloped signature transformation to QIF Document being signed
        etree.SubElement(
            br_transforms,
            'Transform',
            attrib={"Algorithm": "http://www.w3.org/2000/09/xmldsig#enveloped-signature"}
        )
        # No action needed, signature element has already been removed from document
    
    # All references assumed to be XML, all get c14n transformation
    etree.SubElement(
        br_transforms,
        'Transform',
        attrib={"Algorithm": "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"}
    )
    
    doc_string = etree.tostring(document, method="c14n", with_comments=False)
    
    # Use SHA256 as the digest method, SHA1 is not recommended
    etree.SubElement(
        base_reference,
        'DigestMethod',
        attrib={"Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"}
    )
    
    doc_digest = hashlib.sha256(doc_string).digest()
    br_digest_value = etree.SubElement(base_reference, 'DigestValue')
    br_digest_value.text = base64.b64encode(doc_digest)
    logging.info(f"{uri} digested to {base64.b64encode(doc_digest).decode('ascii')}")
    
    return base_reference


def create_signature_element(tree: _ElementTree, sign_algorithm: str) -> Tuple[_Element, _Element]:
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
    signed_info.append(build_reference("", tree))
    
    # Loop through external documents, create digested reference if URI element exists
    ext_qif_docs = tree.iterfind(".//{http://qifstandards.org/xsd/qif3}ExternalQIFDocument")
    for ext_qif_doc in ext_qif_docs:
        qpid = ext_qif_doc.findtext(".//{http://qifstandards.org/xsd/qif3}QPId")
        uri = ext_qif_doc.findtext(".//{http://qifstandards.org/xsd/qif3}URI")
        if uri is not None:
            signed_info.append(build_reference(uri, tree))
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
        sig_val = ec_key.sign(
            sign_info_c14n,
            ec.ECDSA(hashes.SHA256())
        )
    
    return sig_val


def add_signature_value(signature: _Element, sig_val: bytes) -> None:
    """Add SignatureValue to the signature element."""
    signature_value = etree.SubElement(signature, 'SignatureValue')
    signature_value.text = base64.b64encode(sig_val)


def add_key_info(signature: _Element, cert: x509.Certificate) -> None:
    """Add KeyInfo with X509 certificate to the signature element."""
    key_info = etree.SubElement(signature, 'KeyInfo')
    x509_data = etree.SubElement(key_info, 'X509Data')
    x509_cert = etree.SubElement(x509_data, 'X509Certificate')
    x509_cert.text = base64.b64encode(cert.public_bytes(serialization.Encoding.DER))


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
                sig_val,
                sign_info_c14n,
                ec.ECDSA(hashes.SHA256())
            )
    except InvalidSignature:
        raise SystemExit('Unable to validate signature with public key, '
                        'possible mismatch between private key and certificate')


def save_signed_document(tree: _ElementTree, original_filename: str) -> str:
    """Save the signed QIF document with '-signed' appended to filename."""
    type_loc = original_filename.rfind('.')
    if type_loc == -1:
        type_loc = len(original_filename)
    
    file_name = original_filename[:type_loc] + '-signed' + original_filename[type_loc:]
    
    with open(file_name, 'wb') as f:
        tree.write(f, encoding='utf-8', xml_declaration=True)
    
    logging.info(f'Signed QIF document written to file {file_name}')
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
    private_key = load_private_key(args.key, args.keypass, sign_method)
    
    # Create Signature Element
    signature, signed_info = create_signature_element(tree, sign_algorithm)
    
    # Sign the document
    sig_val = sign_document(signed_info, private_key, sign_method)
    
    # Add signature value and key info
    add_signature_value(signature, sig_val)
    add_key_info(signature, cert)
    
    # Verify signature
    verify_signature(public_key, sig_val, signed_info, sign_method)
    
    # Add signature block to QIF Document tree
    qif_root = tree.getroot()
    qif_root.append(signature)
    
    # Save signed document
    save_signed_document(tree, args.qifFile.name)


if __name__ == "__main__":
    main()