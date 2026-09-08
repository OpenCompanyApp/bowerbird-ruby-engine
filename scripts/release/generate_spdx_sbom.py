#!/usr/bin/env python3
"""Create a small SPDX 2.3 dependency and license inventory for an RC archive.

This deliberately reads pinned, checked-out metadata only. It does not claim
that the inventory is a vulnerability scan, an attestation, or a release.
"""
import datetime
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urlparse


def package_id(name, version):
    suffix = hashlib.sha256(f"{name}@{version}".encode()).hexdigest()[:16]
    return f"SPDXRef-Package-{suffix}"


def main():
    metadata_path, engine_lock_path, output_path = map(Path, sys.argv[1:4])
    namespace = sys.argv[4]
    parsed_namespace = urlparse(namespace)
    if parsed_namespace.scheme != "https" or not parsed_namespace.netloc:
        raise SystemExit("SPDX document namespace must be an absolute https URL")
    metadata = json.loads(metadata_path.read_text())
    engine_lock = json.loads(engine_lock_path.read_text())
    workspace_ids = set(metadata["workspace_members"])
    root = next((item for item in metadata["packages"] if item["id"] in workspace_ids), None)
    if root is None:
        raise SystemExit("cargo metadata did not identify a workspace package")
    root_id = package_id(root["name"], root["version"])
    packages = []
    relationships = []
    for item in metadata["packages"]:
        name, version = item["name"], item["version"]
        spdx_id = package_id(name, version)
        packages.append({
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": version,
            "downloadLocation": item.get("repository") or item.get("source") or "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": item.get("license") or "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "filesAnalyzed": False,
        })
        if spdx_id != root_id:
            relationships.append({"spdxElementId": root_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": spdx_id})
    mruby_id = package_id("mruby", engine_lock["commit"])
    packages.append({
        "SPDXID": mruby_id,
        "name": "mruby",
        "versionInfo": engine_lock["version"],
        "downloadLocation": f"git+{engine_lock['upstream']}@{engine_lock['commit']}",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "MIT",
        "primaryPackagePurpose": "LIBRARY",
        "filesAnalyzed": False,
    })
    relationships.append({"spdxElementId": root_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": mruby_id})
    document = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "bowerbird-ruby-engine RC dependency inventory",
        "documentNamespace": namespace,
        "creationInfo": {"created": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"), "creators": ["Tool: bowerbird-ruby-engine/scripts/release/generate_spdx_sbom.py"]},
        "packages": packages,
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}] + relationships,
    }
    output_path.write_text(json.dumps(document, indent=2) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: generate_spdx_sbom.py cargo-metadata engine-lock output namespace")
    main()
