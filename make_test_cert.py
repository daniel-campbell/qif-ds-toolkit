#!/usr/bin/env python3
"""Test Key and Certificate Generator

This program creates a private key and self-signed x509 certificate for trying
out signqif.py and verifyqif.py. A self-signed certificate does not prove who
signed a document; for production, use a certificate issued by a trusted
certificate authority.

External libraries lxml and cryptography are required.

Usage examples:
    # RSA key.pem and cert.cer in the current directory
    python make_test_cert.py
    
    # ECDSA key protected by a password you are prompted for
    python make_test_cert.py --ecdsa --encrypt -key ec-key.pem -cert ec-cert.cer
"""

import argparse
import datetime
import getpass
import os
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID

from signqif import can_prompt


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Program creates a private key and self-signed x509 certificate for testing.'
    )
    parser.add_argument(
        '-key',
        help='Private key file to create, default key.pem',
        default='key.pem'
    )
    parser.add_argument(
        '-cert',
        help='Certificate file to create, default cert.cer',
        default='cert.cer'
    )
    parser.add_argument(
        '--ecdsa',
        help='Create an ECDSA P-256 key instead of RSA 2048',
        action='store_true'
    )
    parser.add_argument(
        '--encrypt',
        help='Protect the private key with a password, prompted for',
        action='store_true'
    )
    parser.add_argument(
        '--name',
        help='Common name for the certificate, default "QIF Test Signer"',
        default='QIF Test Signer'
    )
    parser.add_argument(
        '--days',
        help='Days the certificate is valid, default 365',
        type=int,
        default=365
    )
    return parser.parse_args()


def generate_key(use_ecdsa: bool) -> Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
    """Generate an RSA 2048 or ECDSA P-256 private key."""
    if use_ecdsa:
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_certificate(key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey], name: str, days: int) -> x509.Certificate:
    """Build a self-signed certificate for the key, usable for digital signatures."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=False,
                          crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True
        )
        .sign(key, hashes.SHA256())
    )


def prompt_new_password() -> bytes:
    """Prompt twice for a new password without echoing it."""
    if not can_prompt():
        raise SystemExit('--encrypt needs a terminal to type the password in.')
    try:
        password = getpass.getpass('New key password: ')
        if not password:
            raise SystemExit('Password cannot be empty.')
        if getpass.getpass('Repeat password: ') != password:
            raise SystemExit('Passwords do not match.')
    except (KeyboardInterrupt, EOFError):
        raise SystemExit('Cancelled.')
    return password.encode('utf-8')


def main():
    """Main execution function."""
    args = parse_arguments()
    
    # Never overwrite an existing key, it may be in use
    for path in (args.key, args.cert):
        if os.path.exists(path):
            raise SystemExit(f'{path} already exists, remove it or choose another name.')
    
    encryption = serialization.NoEncryption()
    if args.encrypt:
        encryption = serialization.BestAvailableEncryption(prompt_new_password())
    
    key = generate_key(args.ecdsa)
    cert = build_certificate(key, args.name, args.days)
    
    try:
        with open(args.key, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption))
        with open(args.cert, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    except OSError as e:
        raise SystemExit(f'Unable to write key or certificate: {e}')
    
    key_type = 'ECDSA P-256' if args.ecdsa else 'RSA 2048'
    print(f'Created {key_type} private key {args.key} and self-signed certificate {args.cert} '
          f'for "{args.name}", valid {args.days} days. For testing only.')


if __name__ == "__main__":
    main()
