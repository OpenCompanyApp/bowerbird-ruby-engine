#!/usr/bin/env python3
"""Regression checks for SPDX identity and declared-license boundaries."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("generate_spdx_sbom.py")
SPEC = importlib.util.spec_from_file_location("generate_spdx_sbom", MODULE)
SBOM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SBOM)


class SpdxGenerationTest(unittest.TestCase):
    def test_preserves_https_namespace_and_workspace_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = {"workspace_members": ["path+file:///engine#0.2.7"], "packages": [{"id": "path+file:///engine#0.2.7", "name": "engine", "version": "0.2.7", "license": "Apache-2.0", "repository": "https://example.invalid/engine"}, {"id": "registry+dep#1.0.0", "name": "dep", "version": "1.0.0", "license": "MIT", "source": "registry+https://example.invalid"}]}
            (root / "metadata.json").write_text(json.dumps(metadata))
            (root / "lock.json").write_text(json.dumps({"upstream": "https://github.com/mruby/mruby.git", "version": "4.0.0", "commit": "a" * 40}))
            output = root / "sbom.json"
            import sys
            previous = sys.argv
            sys.argv = ["generate", str(root / "metadata.json"), str(root / "lock.json"), str(output), "https://example.invalid/rc/abc/linux-amd64"]
            try:
                SBOM.main()
            finally:
                sys.argv = previous
            document = json.loads(output.read_text())
            self.assertEqual(document["documentNamespace"], "https://example.invalid/rc/abc/linux-amd64")
            root_id = SBOM.package_id("engine", "0.2.7")
            self.assertEqual(document["relationships"][0]["relatedSpdxElement"], root_id)
            self.assertTrue(all(item["licenseConcluded"] == "NOASSERTION" and item["filesAnalyzed"] is False for item in document["packages"]))


if __name__ == "__main__":
    unittest.main()
