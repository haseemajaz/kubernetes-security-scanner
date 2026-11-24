#!/usr/bin/env python3
"""Kubernetes Security Scanner — safe local demo.

Scans local Kubernetes YAML manifests for misconfigurations.
Reads files only; never connects to a cluster.
Requires PyYAML (see requirements.txt).
"""
import argparse
import json
import sys
from pathlib import Path

import yaml

CHECKS = [
    ("K8S-01", "Critical", "Privileged container", "Remove privileged: true."),
    ("K8S-02", "High", "Container runs as root", "Set runAsUser to a non-root UID and runAsNonRoot: true."),
    ("K8S-03", "High", "Host network / PID / IPC", "Do not use hostNetwork, hostPID, or hostIPC."),
    ("K8S-04", "Medium", "No resource limits", "Set cpu and memory limits for every container."),
    ("K8S-05", "Medium", "Image uses :latest or no tag", "Pin images to a specific digest or version tag."),
    ("K8S-06", "Medium", "Privilege escalation allowed", "Set allowPrivilegeEscalation: false."),
    ("K8S-07", "Low", "Root filesystem is writable", "Set readOnlyRootFilesystem: true."),
    ("K8S-08", "Low", "Service account token auto-mounted", "Set automountServiceAccountToken: false unless the pod needs the API."),
]


def check_container(name, container, pod_spec):
    findings = []
    sec = container.get("securityContext") or {}
    pod_sec = pod_spec.get("securityContext") or {}
    if sec.get("privileged"):
        findings.append(("K8S-01", name))
    if sec.get("runAsUser") == 0 or (pod_sec.get("runAsNonRoot") is not True and sec.get("runAsNonRoot") is not True):
        findings.append(("K8S-02", name))
    if sec.get("allowPrivilegeEscalation") is not False:
        findings.append(("K8S-06", name))
    if sec.get("readOnlyRootFilesystem") is not True:
        findings.append(("K8S-07", name))
    if not (container.get("resources") or {}).get("limits"):
        findings.append(("K8S-04", name))
    image = container.get("image", "")
    if image.endswith(":latest") or ":" not in image:
        findings.append(("K8S-05", name))
    return findings


def check_doc(doc):
    if not isinstance(doc, dict):
        return []
    findings = []
    spec = doc.get("spec", {}) or {}
    template = spec.get("template", {}) or {}
    pod_spec = (template.get("spec") or spec) if template else spec
    if not isinstance(pod_spec, dict):
        return []
    if pod_spec.get("hostNetwork") or pod_spec.get("hostPID") or pod_spec.get("hostIPC"):
        findings.append(("K8S-03", doc.get("metadata", {}).get("name", "?")))
    if pod_spec.get("automountServiceAccountToken") is not False:
        findings.append(("K8S-08", doc.get("metadata", {}).get("name", "?")))
    for container in pod_spec.get("containers", []) or []:
        findings.extend(check_container(container.get("name", "?"), container, pod_spec))
    rule_by_id = {r[0]: r for r in CHECKS}
    return [{"id": rid, "severity": rule_by_id[rid][1], "title": rule_by_id[rid][2],
             "remediation": rule_by_id[rid][3], "resource": resource}
            for rid, resource in findings]


def scan(path):
    findings = []
    files = [path] if path.is_file() else sorted(path.rglob("*.yaml")) + sorted(path.rglob("*.yml"))
    for f in files:
        for doc in yaml.safe_load_all(Path(f).read_text()):
            for finding in check_doc(doc):
                findings.append({**finding, "file": str(f)})
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="YAML file or directory of manifests")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"], default="never")
    args = parser.parse_args()
    findings = scan(Path(args.target))
    if args.format == "json":
        print(json.dumps(findings, indent=2))
    else:
        print(f"Findings: {len(findings)}")
        for f in findings:
            print(f"  [{f['severity']}] {f['id']} {f['title']} — {f['resource']} ({f['file']})")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    if args.fail_on != "never" and any(order[f["severity"].lower()] <= order[args.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
