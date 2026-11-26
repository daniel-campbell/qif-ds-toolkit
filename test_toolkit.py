"""Tests for the QIF digital signature tools

Each test signs the sample QIF document with signqif.py and checks the result
with verifyqif.py. Keys and certificates are created by make_test_cert.py.

Run from the repository directory with:
    python -m unittest
"""

import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from lxml import etree

from make_test_cert import build_certificate, generate_key

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, 'samples', 'nist_ctc_01_asme1_ap242.qif')
DS = '{http://www.w3.org/2000/09/xmldsig#}'


def build_expired_certificate(key, name: str, expired_days: int = 10) -> x509.Certificate:
    """Build a self-signed certificate that expired expired_days ago."""
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=400))
        .not_valid_after(now - datetime.timedelta(days=expired_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


class SignAndVerifyTest(unittest.TestCase):
    """Sign the sample document and verify the result."""
    
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.qif = self.copy_sample('doc.qif')
        self.key, self.cert = self.make_key('signer')
    
    def copy_sample(self, name: str) -> str:
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copy(SAMPLE, path)
        return path
    
    def write_pair(self, name: str, key, cert, password: bytes = None):
        """Write a private key and its certificate to files and return their paths."""
        encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        key_path = os.path.join(self.dir, f'{name}.pem')
        cert_path = os.path.join(self.dir, f'{name}.cer')
        with open(key_path, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption))
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return key_path, cert_path
    
    def make_key(self, name: str, ecdsa: bool = False, password: bytes = None):
        key = generate_key(ecdsa)
        return self.write_pair(name, key, build_certificate(key, name, 30), password)
    
    def make_bundle(self, name: str, *cert_paths: str) -> str:
        """Concatenate certificates into one PEM file, as a chain is usually shipped."""
        bundle_path = os.path.join(self.dir, f'{name}.pem')
        with open(bundle_path, 'wb') as bundle:
            for cert_path in cert_paths:
                with open(cert_path, 'rb') as cert_file:
                    bundle.write(cert_file.read())
        return bundle_path
    
    def run_tool(self, script: str, *args, env: dict = None) -> subprocess.CompletedProcess:
        # Started in an unrelated directory so nothing depends on the working directory
        tool_env = {k: v for k, v in os.environ.items() if k != 'QIF_KEY_PASSWORD'}
        tool_env.update(env or {})
        return subprocess.run([sys.executable, os.path.join(HERE, script), *args], cwd=tempfile.gettempdir(),
                              env=tool_env, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    
    def sign(self, qif: str, *args, key: str = None, cert: str = None, env: dict = None) -> str:
        result = self.run_tool('signqif.py', '-key', key or self.key, '-cert', cert or self.cert, *args, qif, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return qif.replace('.qif', '-signed.qif')
    
    def verify(self, qif: str, *args) -> subprocess.CompletedProcess:
        return self.run_tool('verifyqif.py', *args, qif)
    
    def assertValid(self, qif: str, *args):
        result = self.verify(qif, *args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Result: VALID', result.stdout)
    
    def assertInvalid(self, qif: str, *args, reason: str):
        result = self.verify(qif, *args)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(reason, result.stdout)
    
    def replace_in_file(self, path: str, old: str, new: str):
        with open(path, encoding='utf-8') as f:
            text = f.read()
        self.assertIn(old, text)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text.replace(old, new, 1))
    
    def test_rsa(self):
        self.assertValid(self.sign(self.qif))
    
    def test_ecdsa(self):
        key, cert = self.make_key('ec-signer', ecdsa=True)
        self.assertValid(self.sign(self.qif, key=key, cert=cert))
    
    def test_changed_value_fails(self):
        signed = self.sign(self.qif)
        self.replace_in_file(signed, 'value="0.025"', 'value="0.026"')
        self.assertInvalid(signed, reason='Reference this document: FAILED')
    
    def test_pretty_print_keeps_values(self):
        signed = self.sign(self.qif, '--pretty-print')
        self.assertValid(signed)
    
        def leaf_values(path):
            tree = etree.parse(path)
            return [(e.tag, e.text) for e in tree.iter() if len(e) == 0 and not str(e.tag).startswith(DS)]
        self.assertEqual(leaf_values(self.qif), leaf_values(signed))
    
    def test_trusted_certificate(self):
        signed = self.sign(self.qif)
        self.assertValid(signed, '-cert', self.cert)
        _, other_cert = self.make_key('someone-else')
        self.assertInvalid(signed, '-cert', other_cert, reason='Signature: FAILED')
    
    def test_external_reference(self):
        # Relative to the signed document, which is in a different directory than the tools run in
        qif = self.copy_sample(os.path.join('docs', 'doc.qif'))
        ref = self.copy_sample(os.path.join('docs', 'ref.qif'))
        self.replace_in_file(qif, '<QPId>', '<ExternalQIFReferences n="1"><ExternalQIFDocument id="99999">'
                             '<QPId>00000000-0000-0000-0000-000000000000</QPId><URI>ref.qif</URI>'
                             '</ExternalQIFDocument></ExternalQIFReferences><QPId>')
        signed = self.sign(qif)
        self.assertValid(signed)
    
        self.replace_in_file(ref, 'value="0.025"', 'value="0.026"')
        self.assertInvalid(signed, reason='Reference ref.qif: FAILED')
    
    def test_encrypted_key_password_from_environment(self):
        key, cert = self.make_key('encrypted', password=b'correct horse')
        self.assertValid(self.sign(self.qif, key=key, cert=cert, env={'QIF_KEY_PASSWORD': 'correct horse'}))
    
        result = self.run_tool('signqif.py', '-key', key, '-cert', cert, self.qif, env={'QIF_KEY_PASSWORD': 'wrong'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Incorrect password', result.stderr)
    
    def test_output_path(self):
        output = os.path.join(self.dir, 'sub', 'signed.qif')
        os.makedirs(os.path.dirname(output))
        result = self.run_tool('signqif.py', '-key', self.key, '-cert', self.cert, '-o', output, self.qif)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'Signed {self.qif} -> {output}', result.stdout)
        # The default name is not written when -o is given
        self.assertFalse(os.path.exists(os.path.join(self.dir, 'doc-signed.qif')))
        self.assertValid(output)
    
    def test_output_path_with_several_files_is_refused(self):
        second = self.copy_sample('second.qif')
        result = self.run_tool('signqif.py', '-key', self.key, '-cert', self.cert,
                               '-o', os.path.join(self.dir, 'one.qif'), self.qif, second)
        self.assertEqual(result.returncode, 2)
        self.assertIn('-o/--output can only be used with a single input file', result.stderr)
    
    def test_batch_sign_and_verify(self):
        second = self.copy_sample('second.qif')
        result = self.run_tool('signqif.py', '-key', self.key, '-cert', self.cert, self.qif, second)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Signed 2 documents.', result.stdout)
        first_signed = os.path.join(self.dir, 'doc-signed.qif')
        second_signed = os.path.join(self.dir, 'second-signed.qif')
        
        result = self.run_tool('verifyqif.py', first_signed, second_signed)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('2 of 2 documents valid.', result.stdout)
        
        # One invalid document fails the batch without hiding the valid one
        self.replace_in_file(second_signed, 'value="0.025"', 'value="0.026"')
        result = self.run_tool('verifyqif.py', first_signed, second_signed)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('1 of 2 documents valid.', result.stdout)
        self.assertEqual(result.stdout.count('Result: VALID'), 1)
        self.assertEqual(result.stdout.count('Result: INVALID'), 1)
    
    def test_batch_continues_after_a_failing_file(self):
        broken = os.path.join(self.dir, 'broken.qif')
        with open(broken, 'w', encoding='utf-8') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n<NotAQIFDocument/>\n')
        result = self.run_tool('signqif.py', '-key', self.key, '-cert', self.cert, broken, self.qif)
        self.assertEqual(result.returncode, 1)
        self.assertIn('broken.qif: QIF file does not contain QIFDocument as its root element.', result.stderr)
        self.assertIn('1 of 2 document(s) could not be signed.', result.stderr)
        self.assertValid(os.path.join(self.dir, 'doc-signed.qif'))
    
    def test_signed_name_keeps_directories_out_of_the_way(self):
        # A dot in the directory name and no extension in the file name must not move the output
        qif = self.copy_sample(os.path.join('dir.v1', 'document'))
        result = self.run_tool('signqif.py', '-key', self.key, '-cert', self.cert, qif)
        self.assertEqual(result.returncode, 0, result.stderr)
        signed = os.path.join(self.dir, 'dir.v1', 'document-signed')
        self.assertTrue(os.path.exists(signed), os.listdir(self.dir))
        self.assertValid(signed)
    
    def test_certificate_chain(self):
        # The signer certificate is the second certificate of the file, as in an issued chain
        _, other_cert = self.make_key('other')
        bundle = self.make_bundle('chain', other_cert, self.cert)
        
        signed = self.sign(self.qif, cert=bundle)
        self.assertValid(signed, '-cert', bundle)
        self.assertValid(signed)
        
        # A chain that does not contain the signer certificate is still refused
        _, unrelated_cert = self.make_key('unrelated')
        self.assertInvalid(signed, '-cert', unrelated_cert, reason='Signature: FAILED')
    
    def test_expired_certificate_is_reported(self):
        key = generate_key(False)
        key_path, cert_path = self.write_pair('expired', key, build_expired_certificate(key, 'Expired Signer'))
        result = self.run_tool('signqif.py', '-key', key_path, '-cert', cert_path, self.qif)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('the certificate is outside its validity period', result.stdout)
        
        # The signature itself is still created and verified, the note is informational
        signed = os.path.join(self.dir, 'doc-signed.qif')
        result = self.verify(signed)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('the certificate is outside its validity period', result.stdout)
        self.assertIn('Result: VALID', result.stdout)
    
    def test_mismatched_key_and_certificate(self):
        _, other_cert = self.make_key('other')
        result = self.run_tool('signqif.py', '-key', self.key, '-cert', other_cert, self.qif)
        self.assertEqual(result.returncode, 1)
        self.assertIn('matches the private key', result.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.dir, 'doc-signed.qif')))
    
    def test_json_report(self):
        signed = self.sign(self.qif)
        result = self.verify(signed, '--json')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['result'], 'valid')
        self.assertEqual((report['documents'], report['valid'], report['invalid']), (1, 1, 0))
        document = report['files'][0]
        self.assertEqual(document['result'], 'valid')
        self.assertEqual([reference['uri'] for reference in document['references']], [''])
        self.assertEqual(document['references'][0]['status'], 'ok')
        self.assertEqual(document['signature']['status'], 'ok')
        self.assertEqual(document['certificate']['subject'], 'CN=signer')
        self.assertTrue(document['certificate']['within_validity_period'])
        self.assertEqual(document['certificate']['source'], 'embedded')
        self.assertRegex(document['certificate']['sha256_fingerprint'], r'^([0-9A-F]{2}:){31}[0-9A-F]{2}$')
        
        # A changed document still produces a report, with the reason in it
        self.replace_in_file(signed, 'value="0.025"', 'value="0.026"')
        result = self.verify(signed, '--json')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['result'], 'invalid')
        self.assertEqual(report['invalid'], 1)
        reference = report['files'][0]['references'][0]
        self.assertEqual(reference['status'], 'failed')
        self.assertIn('digest does not match', reference['problem'])
    
    def test_json_report_for_unusable_document(self):
        unsigned = self.qif
        result = self.verify(unsigned, '--json')
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report['result'], 'invalid')
        self.assertIn('no Signature element found', report['files'][0]['error'])


if __name__ == '__main__':
    unittest.main()
