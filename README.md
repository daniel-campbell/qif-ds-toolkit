# QIF Digital Signature Toolkit

Tools for signing QIF (Quality Information Framework) documents with XML digital signatures, and for verifying those signatures.

- `signqif.py` signs a QIF document, and any external QIF documents it references, embedding the signature and signer certificate in the document.
- `verifyqif.py` checks that a signed QIF document, and any external QIF documents it references, have not changed since signing, and shows who signed it.
- `make_test_cert.py` creates a private key and self-signed certificate for trying out the tools.

The tools follow the W3C XML Signature standard and support RSA and ECDSA keys. They run on Windows, macOS and Linux.

## Requirements

- Python 3.11 or higher
- Python packages `lxml` (XML processing) and `cryptography` (cryptographic operations), listed in `requirements.txt`

## Installation

Create a virtual environment and install the dependencies.

macOS and Linux:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Windows (PowerShell):
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Activate the virtual environment again in each new terminal before running the tools.

## Quick Start

```bash
python make_test_cert.py
python signqif.py -key key.pem -cert cert.cer samples/nist_ctc_01_asme1_ap242.qif
python verifyqif.py samples/nist_ctc_01_asme1_ap242-signed.qif
```

## Creating a Test Key and Certificate

```bash
python make_test_cert.py
```

This creates an RSA private key `key.pem` and a self-signed certificate `cert.cer` in the current directory. A self-signed certificate does not prove who signed a document; for production, use a certificate issued by a certificate authority your recipients trust.

| Option | Description |
|--------|-------------|
| `-key KEY` | Private key file to create, default `key.pem` |
| `-cert CERT` | Certificate file to create, default `cert.cer` |
| `--ecdsa` | Create an ECDSA P-256 key instead of RSA 2048 |
| `--encrypt` | Protect the private key with a password, which you are prompted for |
| `--name NAME` | Common name in the certificate, default `QIF Test Signer` |
| `--days DAYS` | Days the certificate is valid, default 365 |

Existing files are never overwritten. If you have OpenSSL, `openssl req -x509 -newkey rsa:2048 -noenc -keyout key.pem -out cert.cer` creates an equivalent pair.

## Signing a QIF Document

```bash
python signqif.py -key key.pem -cert cert.cer document.QIF
```

The signed document is written next to the input with `-signed` added to its name, so `document.QIF` becomes `document-signed.QIF`. Any existing signature in the input is replaced.

| Option | Required | Description |
|--------|----------|-------------|
| `qifFile` | Yes | QIF file to be signed |
| `-key KEY` | Yes | Private key file in PEM format |
| `-cert CERT` | Yes | x509 certificate file in PEM format, matching the private key |
| `--pretty-print` | No | Indent the output XML for readability |
| `-v` | No | Verbose output |

### Formatting

- **Default**: newlines between elements, no indentation
- **With `--pretty-print`**: indented with 2 spaces per level, including the signature

Either way, only whitespace between elements is changed; element values are written exactly as they appear in the input.

### External QIF Documents

If the document lists external QIF documents with a `URI`, each one is signed as well, so verification fails if any of them changes. Relative URIs are resolved against the signed document's location, as the XML Signature standard requires. Local files only: relative paths, absolute paths and `file:` URIs.

### Password-Protected Keys

If the private key is encrypted, the tool prompts for its password when it runs. The password is not shown as you type, and you get three attempts.

```
$ python signqif.py -key key.pem -cert cert.cer document.QIF
Password for key.pem:
```

For unattended signing, such as in a CI pipeline, set the `QIF_KEY_PASSWORD` environment variable instead, preferably from your CI system's secret store. If the key is encrypted, no terminal is available and the variable is not set, the tool exits with an error rather than waiting for input.

Passwords cannot be given on the command line, where they would be visible to other users and saved in shell history.

## Verifying a Signed QIF Document

```bash
python verifyqif.py document-signed.QIF
```

```
Reference this document: OK
Signature: OK
Signed with certificate:
  Subject:     CN=QIF Test Signer
  Issuer:      CN=QIF Test Signer
  Valid:       2026-10-20 to 2027-10-20
  Fingerprint: SHA256 F6:9D:B0:B3:...
  Checked against the certificate embedded in the file. This shows the document has not changed since it was signed, not who signed it. Use -cert to require a certificate you trust.
Result: VALID
```

The tool exits with status 0 if the signature is valid and 1 if it is not, so it can be used in scripts.

| Option | Required | Description |
|--------|----------|-------------|
| `qifFile` | Yes | Signed QIF file to be verified |
| `-cert CERT` | No | x509 certificate in PEM format that the document must be signed with |
| `-v` | No | Verbose output |

### Who Signed It

Without `-cert`, the signature is checked against the certificate embedded in the document. That proves the document has not changed since it was signed, but anyone can embed their own certificate, so it does not prove who signed it. To require a specific signer, give the certificate you trust:

```bash
python verifyqif.py -cert trusted.cer document-signed.QIF
```

### Other Signers and Tools

`verifyqif.py` also verifies QIF documents signed by other XML Signature tools, provided they use whole-document references with the common algorithms: RSA or ECDSA with SHA-256, SHA-384 or SHA-512, and inclusive or exclusive XML canonicalization.

Documents signed by `signqif.py` can also be verified with other tools, such as `xmlsec1 --verify --trusted-pem cert.cer document-signed.QIF`. If the document references external QIF documents, run `xmlsec1` from the signed document's directory, because `xmlsec1` resolves relative URIs against the current directory rather than the document's location.

## Running the Tests

From the repository directory, with the virtual environment active:

```bash
python -m unittest
```

The tests sign the sample document with RSA and ECDSA keys, and check that verification succeeds, and that it fails when the document, an external document or the expected certificate changes.

## Security Considerations

- **Private key protection**: keep private keys secure, protect production keys with a password, and never commit them to version control
- **Certificates**: use certificates from a certificate authority your recipients trust in production; self-signed certificates are for testing
- **Key strength**: use at least 2048-bit RSA keys or equivalent ECDSA keys
- **Passwords**: use strong passwords for password-protected keys
- **Verification**: verify with `-cert` and a certificate you trust before relying on who signed a document

## Troubleshooting

**"Unable to parse XML from QIF file"**
- The input file must be well-formed XML; the message includes the parser's error and line number

**"QIF file does not contain QIFDocument as its root element"**
- The input file must be a QIF document with root element `QIFDocument` in the namespace `http://qifstandards.org/xsd/qif3`

**"Private key does not contain a recognized cryptosystem or does not match certificate cryptosystem"**
- Only RSA and ECDSA keys in PEM format are supported, and the key and certificate must be the same type

**"Unable to validate signature with public key"**
- The private key does not match the certificate

**"Reference ... FAILED" when verifying**
- The named document has changed since it was signed, or an external document could not be found next to the signed document

Run either tool with `-v` for more detail.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

This project uses the following open-source libraries:
- **lxml**: BSD License
- **cryptography**: Apache License 2.0 / BSD License
