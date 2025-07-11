# QIF Digital Signature Toolkit

Toolkit for applying XML digital signatures to QIF (Quality Information Framework) documents.

## Requirements

- Python 3.7 or higher
- OpenSSL (for certificate generation)
- xmlsec1 (optional, for signature verification)

### Python Dependencies

- `lxml` - XML processing library
- `cryptography` - Cryptographic operations

## Overview

This toolkit creates XML digital signatures for QIF documents and any external QIF documents they reference. It supports RSA and ECDSA cryptographic methods and embeds the signature and certificate into the QIF document according to XML digital signature standards.

## Installation

Create a virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install lxml cryptography
```

## Usage

### Generate Test Certificate and Key

Create a self-signed certificate for testing:

```bash
openssl req -x509 -newkey rsa:2048 -noenc -keyout key.pem -out cert.cer
```

### Sign a QIF Document

Basic usage:
```bash
source venv/bin/activate
python signqif.py -key key.pem -cert cert.cer input.QIF
```

With verbose output:
```bash
python signqif.py -v -key key.pem -cert cert.cer input.QIF
```

With password-protected key:
```bash
python signqif.py -key key.pem -keypass yourpassword -cert cert.cer input.QIF
```

### Verify Signature

Verify the signed document (requires xmlsec1):
```bash
xmlsec1 --verify --trusted-pem cert.cer input-signed.QIF
```

## Command Line Options

| Option | Required | Description |
|--------|----------|-------------|
| `qifFile` | Yes | QIF file to be signed (positional argument) |
| `-key KEY` | Yes | Private key file in PEM format |
| `-cert CERT` | Yes | x509 certificate file in PEM format |
| `-keypass KEYPASS` | No | Password for private key (if password-protected) |
| `-v` | No | Enable verbose output for detailed logging |
| `--pretty-print` | No | Format output XML with indentation for readability |
| `-h, --help` | No | Show help message and exit |

### Examples

**Basic signing:**
```bash
python signqif.py -key private.pem -cert certificate.cer document.QIF
```

**With password-protected key:**
```bash
python signqif.py -key private.pem -keypass mypassword -cert certificate.cer document.QIF
```

**With verbose logging:**
```bash
python signqif.py -v -key private.pem -cert certificate.cer document.QIF
```

**With pretty-printed output:**
```bash
python signqif.py --pretty-print -key private.pem -cert certificate.cer document.QIF
```

## Output

The tool creates a new QIF file with "-signed" appended to the original filename. For example, `document.QIF` becomes `document-signed.QIF`.

### Formatting Options

- **Default**: Output has newlines between elements but zero indentation (each element starts at column 0)
- **With `--pretty-print`**: Output is formatted with consistent indentation (2 spaces) for improved readability

## Features

- Supports RSA and ECDSA cryptographic methods
- Creates digest values for main document and external references
- Removes existing signatures before signing
- Validates signature with public key before output
- Comprehensive logging with verbose mode

## Security Considerations

⚠️ **Important Security Notes:**

- **Private Key Protection**: Keep your private keys secure and never commit them to version control
- **Certificate Validation**: Ensure certificates are from trusted sources in production environments
- **Key Strength**: Use at least 2048-bit RSA keys or equivalent ECDSA key strength
- **Password Security**: Use strong passwords for password-protected keys
- **Signature Verification**: Always verify signatures using trusted certificates before accepting signed documents

### Recommended Practices

1. **Generate keys securely**: Use proper entropy sources when generating cryptographic keys
2. **Store keys safely**: Use hardware security modules (HSMs) or secure key storage for production
3. **Regular rotation**: Rotate signing keys according to your security policy
4. **Audit trail**: Maintain logs of signing operations for security auditing

## Troubleshooting

### Common Issues

**"Unable to parse XML from QIF file"**
- Ensure the input file is valid XML
- Check file permissions and encoding
- Verify the file is not corrupted

**"QIF file does not contain QIFDocument as its root element"**
- The input file must be a valid QIF document
- Check that the root element has the correct namespace: `http://qifstandards.org/xsd/qif3`

**"Unable to validate signature with public key"**
- Ensure the private key matches the certificate
- Check that the private key is not corrupted
- Verify the certificate is valid and not expired

**"Private key does not contain a recognized cryptosystem"**
- Only RSA and ECDSA keys are supported
- Ensure the private key file is in PEM format
- Check that the key was generated correctly

### Getting Help

If you encounter issues:
1. Run with `-v` flag for verbose output
2. Check that all dependencies are properly installed
3. Verify file permissions and paths
4. Ensure OpenSSL is available for certificate operations

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

This project uses the following open-source libraries:
- **lxml**: BSD License
- **cryptography**: Apache License 2.0 / BSD License