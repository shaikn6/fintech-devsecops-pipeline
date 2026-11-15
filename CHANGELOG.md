# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added
- Python unit tests for the compliance reporter (`scripts/test_compliance_reporter.py`, standard-library `unittest`) covering score weighting, Trivy severity parsing, and the CLI's success and failure paths
- `python-tests` hard gate in `ci-security.yml` that runs the reporter unit tests and feeds the compliance summary
- `ServiceAccount` template in the Helm chart (`serviceAccount.create/name/annotations`); the chart previously referenced a service account it did not create
- Rego unit tests (`policies/rego/*_test.rego`, `policies/conftest/main_test.rego`) run with `opa test` in CI
- Conftest gate that evaluates the rendered Helm chart against the admission policies (`policies/conftest/main.rego`)
- `aws_default_security_group` with no rules in the `vpc` module
- Allow-path Rego tests for alternative compliant inputs (non-root UID without `runAsNonRoot`, extra dropped capabilities, pod-selector ingress, private-CIDR egress, a compliant NetworkPolicy manifest through Conftest)

### Changed
- README corrected for honesty: the local checks run "with no AWS credentials or backend" rather than "fully offline" (`terraform init` downloads providers), and the weekly scan is described accurately — all scanners upload artifacts, but the compliance score is computed from the Trivy filesystem scan and `--framework` is a report label, not a per-framework mapping
- Rego `deny` rules now use `deny contains msg if`, so they evaluate as a set under OPA 1.x
- Chart NetworkPolicies declare both `Ingress` and `Egress` policy types, as the network policy requires
- VPC flow-log IAM policy scoped to the flow-log log group instead of `*`
- `data.aws_region.current.name` replaced with the non-deprecated `region` attribute
- Third-party GitHub Actions pinned to release tags instead of `@master`
- Security group egress in the `eks` and `vpc` modules is no longer allow-all: the control plane reaches only the nodes, nodes reach each other and HTTPS, and the interface-endpoint group has no egress
- Default log retention for EKS control plane logs and VPC flow logs raised from 90 to 365 days

### Fixed
- `scripts/compliance_reporter.py` silently reported a 100% score when the scan file passed to `--vuln-file` was missing or unparseable; it now exits non-zero with an error so a failed scan cannot pass as clean
- Duplicate label keys in the Deployment pod template
- The node security group was never attached to the node launch template, so its rules did not apply
- Capability-drop policy did not fire when a container had no `capabilities` block
- Pod label policy did not fire when a Pod had no labels at all
- README quickstart no longer copies `.env.example`; no command, workflow or script reads `.env`, so the unused file was removed

## [1.0.0] - 2026-06-16

Initial reference implementation. Nothing in this repo has been deployed to a
live environment.

### Added
- Terraform modules for AWS EKS and VPC provisioning, with IMDSv2-enforced node launch templates
- Helm chart for the fintech API workload, including NetworkPolicy templates
- ArgoCD GitOps deployment (Application/AppProject manifests) for automated sync from Git
- OPA/Rego policies for container security, image signing, and network policy enforcement
- Checkov static analysis for Terraform and Kubernetes manifests in CI

### Security
- Kubernetes RBAC manifests scoping workload permissions
- Rego policy denying unsigned or `:latest`-tagged container images
