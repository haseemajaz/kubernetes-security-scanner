# Architecture — Kubernetes Security Scanner

## Flow

```
manifests/*.yaml  →  yaml.safe_load_all  →  check_doc() per document
  →  check_container() per container  →  findings (id, severity, title, remediation, file)
  →  text / JSON output, optional non-zero exit code for CI
```

## Components

| Piece | Role |
|---|---|
| `k8s_scanner.py: CHECKS` | The ruleset, with severity and remediation per check |
| `check_doc()` | Pod-level checks: host namespaces, service-account token |
| `check_container()` | Container-level checks: privilege, root user, limits, image tag |
| `manifests/` | One deliberately insecure manifest and one clean manifest, so the scanner can be demoed both ways |

## Design decisions

- **Local files only, no cluster access.** A scanner that needs kubeconfig cannot be reviewed safely; a manifest scanner shows the same checks.
- **PyYAML `safe_load_all`.** Handles multi-document files and never executes YAML tags.
- **CI-shaped output.** `--format json` and `--fail-on high` let the same tool run in a pipeline, which is how employers actually use it.
- **Checks are data, not branches.** Adding a check means adding a `CHECKS` entry and a few lines in `check_doc` / `check_container`.

## How to extend

1. Add RBAC checks: scan `Role` / `ClusterRole` docs for wildcard verbs.
2. Add image checks: flag images from untrusted registries.
3. Add Pod Security Standards mapping: label each finding `restricted` / `baseline` / `privileged`.
