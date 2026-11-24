# 10 — Kubernetes Security Scanner

**Area:** Security Engineering · **Stack:** Python 3.10+, PyYAML · **Status:** Portfolio starter, safe local demo

## What it does

Scans Kubernetes YAML manifests for common misconfigurations, the kind that show up in real cluster audits:

- Containers running as root / privileged
- `hostNetwork`, `hostPID`, `hostIPC` enabled
- No resource limits
- Images using `:latest` or with no tag
- `runAsNonRoot` not set, `allowPrivilegeEscalation` not disabled
- `readOnlyRootFilesystem` not set
- Secrets mounted as environment variables (flagged for review)
- Default service account / automount of the service-account token

It reads one file or a whole directory, prints findings by severity, and can write JSON for CI. Sample manifests are in `manifests/`: `insecure-deployment.yaml` (many findings, on purpose) and `secure-deployment.yaml` (clean).

## What an employer sees

- You know the Kubernetes security model: pod security, RBAC-adjacent risks, image hygiene
- Your checks map to named controls (CIS Kubernetes Benchmark / Pod Security Standards)
- The scanner is CI-shaped: exit code 1 when a High/Critical finding exists, JSON output for pipelines

## How to run

```bash
cd 10-kubernetes-security-scanner
pip install -r requirements.txt

python3 k8s_scanner.py manifests/insecure-deployment.yaml
python3 k8s_scanner.py manifests/secure-deployment.yaml
python3 k8s_scanner.py manifests/ --format json
python3 k8s_scanner.py manifests/ --fail-on high
```

## Try it yourself

Copy `manifests/secure-deployment.yaml`, change `runAsNonRoot` to `false`, re-run, and watch the finding appear.

## Safety

Educational only. This scanner reads local YAML files only. It never connects to a cluster, never needs kubeconfig, and must not be used to probe a cluster you do not own or have written permission to assess.
