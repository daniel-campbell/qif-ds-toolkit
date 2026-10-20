"""Tests for the QIF digital signature tools

Each test signs the sample QIF document with signqif.py and checks the result
with verifyqif.py. Keys and certificates are created by make_test_cert.py.

Run from the repository directory with:
    python -m unittest
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from lxml import etree

from make_test_cert import build_certificate, generate_key

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, 'samples', 'nist_ctc_01_asme1_ap242.qif')
DS = '{http://www.w3.org/2000/09/xmldsig#}'


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
    
    def make_key(self, name: str, ecdsa: bool = False, password: bytes = None):
        key = generate_key(ecdsa)
        encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        key_path = os.path.join(self.dir, f'{name}.pem')
        cert_path = os.path.join(self.dir, f'{name}.cer')
        with open(key_path, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption))
        with open(cert_path, 'wb') as f:
            f.write(build_certificate(key, name, 30).public_bytes(serialization.Encoding.PEM))
        return key_path, cert_path
    
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


if __name__ == '__main__':
    unittest.main()
