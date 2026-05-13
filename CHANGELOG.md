# Changelog

All notable changes to this project are documented here.

## [1.0.0] - 2026-06-16

### Added
- SAST integration with Semgrep and Bandit scanning every pull request for injection and logic vulnerabilities
- DAST pipeline using OWASP ZAP against staging environments with automated issue ticketing
- SBOM generation in CycloneDX format with automated CVE correlation via OSV and NVD feeds
- Container image signing with Cosign and policy enforcement via OPA admission controller on AWS EKS
- ArgoCD GitOps deployment with automated drift detection and self-healing for production workloads
- PCI-DSS and SOC 2 compliance report generation from pipeline scan artifacts and audit logs

### Changed
- Production-ready CI/CD with 95%+ test coverage enforcement

### Security
- All secrets managed via AWS Secrets Manager with automatic rotation; zero hardcoded credentials in pipeline config
