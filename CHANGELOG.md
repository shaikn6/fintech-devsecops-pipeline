# Changelog

All notable changes to this project are documented here.

## [1.0.0] - 2026-06-16

### Added
- Terraform modules for AWS EKS and VPC provisioning, with IMDSv2-enforced node launch templates
- Helm chart for the fintech API workload, including RBAC and NetworkPolicy templates
- ArgoCD GitOps deployment (Application/AppProject manifests) for automated sync from Git
- OPA/Rego policies for container security, image signing, and network policy enforcement
- Checkov static analysis for Terraform and Kubernetes manifests in CI

### Security
- Kubernetes RBAC manifests scoping workload permissions
- Rego policy denying unsigned or `:latest`-tagged container images
