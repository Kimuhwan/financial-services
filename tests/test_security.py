"""Offline security regressions; no external requests or agent workflows.

Run: python3 -m unittest discover -s tests -v
Requires the bootstrap requirements plus httpx (FastAPI's test client).
"""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

ROOT = Path(os.environ.get("FINANCIAL_SECURITY_TEST_ROOT", Path(__file__).resolve().parents[1]))
BOOTSTRAP = ROOT / "claude-for-msft-365-install/examples/python-bootstrap"
MANIFEST = ROOT / "claude-for-msft-365-install/scripts/build-manifest.mjs"


class BootstrapSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwks = Path(cls.temp.name) / "jwks.json"
        jwks.write_text(json.dumps({"keys": [jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key(), as_dict=True)]}))
        with patch.dict(os.environ, {"TENANT_ID": "test-tenant", "HOST": "127.0.0.1", "DEV_JWKS_PATH": str(jwks)}):
            for name in ("config", "app"):
                spec = importlib.util.spec_from_file_location(name, BOOTSTRAP / f"{name}.py")
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
            cls.module = sys.modules["app"]
        cls.client = TestClient(cls.module.app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.temp.cleanup()
        for name in ("config", "app"):
            sys.modules.pop(name, None)

    def token(self, updates=None, remove=()):
        claims = {"aud": self.module.AUDIENCE, "iss": self.module.ISSUER,
                  "oid": "alice", "groups": ["investment-banking"], "exp": int(time.time()) + 60}
        claims.update(updates or {})
        for name in remove:
            claims.pop(name, None)
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "test"})

    def request(self, token):
        return self.client.get("/bootstrap", headers={"Authorization": "Bearer " + token,
                                                      "X-Claude-User-Agent": "claude-word/1.0.0"})

    def test_valid_user_and_group_still_resolve(self):
        response = self.request(self.token())
        self.assertEqual(response.status_code, 200)
        self.assertEqual([s["name"] for s in response.json()["skills"]], ["deal-memo", "compliance-check"])

    def test_user_response_is_not_cached(self):
        self.assertEqual(self.request(self.token()).headers.get("cache-control"), "no-store")

    def test_missing_security_claims_are_rejected(self):
        for name in ("exp", "aud", "iss", "oid"):
            with self.subTest(claim=name):
                self.assertEqual(self.request(self.token(remove=[name])).status_code, 401)

    def test_invalid_identities_are_rejected(self):
        for value in ("", " ", 123, ["alice"], {}):
            with self.subTest(identity_type=type(value).__name__):
                self.assertEqual(self.request(self.token({"oid": value})).status_code, 401)

    def test_invalid_group_shapes_are_rejected(self):
        for value in (None, "risk", {"risk": True}, [123], [["risk"]]):
            with self.subTest(groups_type=type(value).__name__):
                self.assertEqual(self.request(self.token({"groups": value})).status_code, 401)

    def test_absent_groups_still_support_user_rules(self):
        self.assertEqual(self.request(self.token(remove=["groups"])).status_code, 200)

    def test_expired_wrong_issuer_and_wrong_audience_rejected(self):
        for changes in ({"exp": 1}, {"iss": "https://invalid.example"}, {"aud": "other"}):
            with self.subTest(claim=next(iter(changes))):
                self.assertEqual(self.request(self.token(changes)).status_code, 401)

    def test_invalid_signature_rejected(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        claims = {"aud": self.module.AUDIENCE, "iss": self.module.ISSUER, "oid": "alice", "exp": int(time.time()) + 60}
        token = jwt.encode(claims, other, algorithm="RS256")
        self.assertEqual(self.request(token).status_code, 401)

    def test_signing_key_errors_return_generic_401(self):
        class FailingKeys:
            def get_signing_key_from_jwt(self, token):
                raise jwt.PyJWKClientError("internal key-resolution details")
        with patch.object(self.module, "DEV_JWKS_PATH", None), patch.object(self.module, "_jwks", FailingKeys()):
            response = self.request("invalid")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Invalid bearer token"})

    def test_missing_and_malformed_tokens_rejected(self):
        self.assertEqual(self.client.get("/bootstrap").status_code, 401)
        self.assertEqual(self.request("not.a.jwt").status_code, 401)


class DevKeySecurityTests(unittest.TestCase):
    def test_new_dev_private_key_is_owner_only_even_with_open_umask(self):
        driver = "import os, runpy; os.umask(0); runpy.run_path(os.environ['MINT_SCRIPT'], run_name='__main__')"
        with tempfile.TemporaryDirectory() as temp:
            result = subprocess.run([sys.executable, "-c", driver], cwd=temp, capture_output=True, text=True,
                                    env={**os.environ, "MINT_SCRIPT": str(BOOTSTRAP / "mint_dev_token.py")}, check=False)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(stat.S_IMODE((Path(temp) / "dev_private.pem").stat().st_mode), 0o600)


class ManifestLogSecurityTests(unittest.TestCase):
    # Fetch is replaced before the script loads; never contact the manifest host.
    DRIVER = r'''
      import {pathToFileURL} from 'node:url';
      const script = process.argv[1];
      const args = JSON.parse(process.argv[2]);
      globalThis.fetch = async () => new Response('<SourceLocation DefaultValue="https://example.invalid/?m=office"/><bt:Url id="Taskpane.Url" DefaultValue="https://example.invalid/?m=office"/>');
      process.argv = ['node', script, ...args];
      await import(pathToFileURL(script));
    '''

    def run_manifest(self, pairs):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "manifest.xml"
            result = subprocess.run(["node", "--input-type=module", "-e", self.DRIVER, str(MANIFEST),
                                     json.dumps(["office", str(output), *pairs])], capture_output=True, text=True, check=False)
            xml = output.read_text() if output.exists() else ""
        return result, xml

    def test_values_never_appear_in_logs_but_manifest_is_preserved(self):
        marker = "SYNTHETIC_SECURITY_TEST_VALUE"
        pairs = [f"gateway_token={marker}", f"azure_api_key={marker}", f"google_client_secret={marker}",
                 'inference_headers={"Authorization":"' + marker + '"}']
        result, xml = self.run_manifest(pairs)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(marker, result.stdout + result.stderr)
        self.assertIn(marker, xml)
        self.assertIn("gateway_token", result.stdout)

    def test_malformed_arguments_do_not_echo_values(self):
        marker = "SYNTHETIC_MALFORMED_SECRET"
        result, _ = self.run_manifest([marker])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(marker, result.stdout + result.stderr)

    def test_unknown_keys_do_not_echo_input(self):
        marker = "SYNTHETIC_MISTYPED_SECRET"
        result, _ = self.run_manifest([marker + "=value"])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(marker, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
