# QIF Digital Signature Toolkit

Tools for signing QIF (Quality Information Framework) documents with XML digital signatures, and for verifying those signatures.

- `signqif.py` signs one or more QIF documents, and any external QIF documents they reference, embedding the signature and signer certificate in each document.
- `verifyqif.py` checks that each signed QIF document, and any external QIF documents it references, have not changed since signing, and shows who signed it. It can also report the result as JSON, for scripts.
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
| `qifFile` | Yes | One or more QIF files to be signed |
| `-key KEY` | Yes | Private key file in PEM format |
| `-cert CERT` | Yes | x509 certificate file in PEM format, matching the private key. A file holding several certificates, such as an issued chain, is accepted: the certificate that matches the key is used and embedded |
| `-o OUT` | No | Write the signed document to this path instead of `<name>-signed.<ext>`. Only with a single input file |
| `--pretty-print` | No | Indent the output XML for readability |
| `-v` | No | Verbose output |

Each document is reported as it is signed:

```
Signed document.QIF -> document-signed.QIF
Signer certificate: CN=QIF Test Signer, SHA256 F6:9D:B0:B3:...
```

If the certificate is outside its validity period today, a note is printed as well. The signature is still created, since a document does not record when it was signed and your policy decides whether an expired certificate matters.

### Signing Several Documents

Give as many files as you need, for example a whole batch of plans or results:

```bash
python signqif.py -key key.pem -cert cert.cer plans/*.qif
```

Every file is signed on its own. A file that cannot be signed is reported on standard error with its name, the remaining files are still processed, and the tool exits with status 1. The key, the certificate and the password are read once, so a protected key is only prompted for once per run. `-o` cannot be combined with several input files, since they would all write to the same path.

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
| `qifFile` | Yes | One or more signed QIF files to be verified |
| `-cert CERT` | No | x509 certificate in PEM format that the documents must be signed with. A file holding several certificates, such as an issued chain, is accepted |
| `--json` | No | Print a machine-readable JSON report instead of the text summary |
| `-v` | No | Verbose output |

### Who Signed It

Without `-cert`, the signature is checked against the certificate embedded in the document. That proves the document has not changed since it was signed, but anyone can embed their own certificate, so it does not prove who signed it. To require a specific signer, give the certificate you trust:

```bash
python verifyqif.py -cert trusted.cer document-signed.QIF
```

### Verifying Several Documents

List as many signed documents as you need, such as everything a batch of measurements produced:

```bash
python verifyqif.py signed/*.QIF
```

Each document is reported under a `== path ==` heading, and the last line counts them:

```
2 of 3 documents valid.
```

A document that cannot be read or is not signed is reported on standard error and counted as invalid, without stopping the rest. The exit status is 0 only when every document is valid, so the whole batch can gate a script.

### Machine-Readable Output

For a pipeline, `--json` prints one JSON object instead of the text:

```bash
python verifyqif.py --json -cert trusted.cer document-signed.QIF
```

```json
{
  "files": [
    {
      "file": "document-signed.QIF",
      "references": [{"uri": "", "status": "ok", "problem": null}],
      "signature": {"status": "ok", "reason": null},
      "certificate": {
        "subject": "CN=QIF Test Signer",
        "issuer": "CN=QIF Test Signer",
        "not_valid_before": "2026-10-20",
        "not_valid_after": "2027-10-20",
        "within_validity_period": true,
        "sha256_fingerprint": "F6:9D:B0:B3:...",
        "source": "argument"
      },
      "result": "valid"
    }
  ],
  "documents": 1,
  "valid": 1,
  "invalid": 0,
  "result": "valid"
}
```

`references` has one entry per signed document, with the URI as written in the signature (`""` is the document itself) and the reason when a digest does not match. `certificate.source` is `argument` when `-cert` was given and `embedded` otherwise. A document that could not be checked at all carries an `error` string instead of the reference and signature details. The exit status is the same as for the text output.

### Other Signers and Tools

`verifyqif.py` also verifies QIF documents signed by other XML Signature tools, provided they use whole-document references with the common algorithms: RSA or ECDSA with SHA-256, SHA-384 or SHA-512, and inclusive or exclusive XML canonicalization.

Documents signed by `signqif.py` can also be verified with other tools, such as `xmlsec1 --verify --trusted-pem cert.cer document-signed.QIF`. If the document references external QIF documents, run `xmlsec1` from the signed document's directory, because `xmlsec1` resolves relative URIs against the current directory rather than the document's location.

## Running the Tests

From the repository directory, with the virtual environment active:

```bash
python -m unittest
```

The tests sign the sample document with RSA and ECDSA keys, and check that verification succeeds, and that it fails when the document, an external document or the expected certificate changes. They also cover signing several documents and checking them in one run, writing to a chosen path, certificate files that hold a chain, an expired certificate, a key that does not match the certificate, and the JSON report.

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

**"Private key does not contain a recognized cryptosystem, allowable types are RSA and ECDSA"**
- Only RSA and ECDSA keys in PEM format are supported, and the key must match the certificate

**"None of the certificates in CERT matches the private key KEY"**
- The key and the certificate do not belong together, or the certificate file holds a chain for a different key. Check that `-key` and `-cert` come from the same key pair

**"Unable to validate signature with public key"**
- The private key and the certificate's public key do not produce the same signature. This is reported when signing, before anything is written

**"-o/--output can only be used with a single input file"**
- Sign one file per run with `-o`, or leave `-o` out to get the `-signed` names

**"Reference ... FAILED" when verifying**
- The named document has changed since it was signed, or an external document could not be found next to the signed document

Run either tool with `-v` for more detail.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

This project uses the following open-source libraries:
- **lxml**: BSD License
- **cryptography**: Apache License 2.0 / BSD License
