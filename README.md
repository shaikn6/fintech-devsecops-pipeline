<p align="center"><img src=".github/banner.png" alt="fintech-devsecops-pipeline" width="100%"></p>

<div align="center">

# Fintech DevSecOps Pipeline

[![CI](https://github.com/shaikn6/fintech-devsecops-pipeline/actions/workflows/ci-security.yml/badge.svg)](https://github.com/shaikn6/fintech-devsecops-pipeline/actions)
[![Terraform](https://img.shields.io/badge/Terraform-1.8+-purple?logo=terraform)](https://terraform.io)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.29+-blue?logo=kubernetes)](https://kubernetes.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![ArgoCD](https://img.shields.io/badge/ArgoCD-GitOps-orange)](https://argoproj.github.io/cd/)

**Production-grade DevSecOps pipeline for fintech — Terraform + EKS + ArgoCD + OPA policy enforcement**

</div>

## Architecture

```mermaid
graph TD
    A[Developer Push] --> B[GitHub Actions CI]
    B --> C[Trivy SAST + SCA Scan]
    C --> D[OPA/Conftest Policy Gate]
    D --> E[ECR Image Push]
    E --> F[ArgoCD Sync]
    F --> G[EKS Cluster]
    G --> H[dev overlay]
    G --> I[prod overlay]
    subgraph IaC
      J[Terraform VPC]
      K[Terraform EKS]
      L[Terraform IAM]
    end
```

## Key Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| CI/CD | GitHub Actions | Lint → scan → deploy |
| Security scanning | Trivy + Bandit | SAST + SCA |
| Policy enforcement | OPA + Conftest | Kubernetes admission |
| Infrastructure | Terraform | VPC, EKS, IAM, ECR |
| GitOps | ArgoCD | App delivery |
| Compliance | Custom scan | SOC2 / PCI controls |

## Quick Start

```bash
git clone https://github.com/shaikn6/fintech-devsecops-pipeline
cd fintech-devsecops-pipeline && cp .env.example .env

# Provision infrastructure
cd terraform/environments/dev
terraform init && terraform apply

# ArgoCD bootstrap
kubectl apply -f k8s/argocd/
```

## Directory Structure

```
├── .github/workflows/    # CI security, CD deploy, compliance scan
├── k8s/                  # Kustomize base + dev/prod overlays + ArgoCD apps
├── policies/             # OPA Rego policies + Conftest tests
├── terraform/            # VPC, EKS, IAM, ECR modules
└── scripts/              # Utility scripts
```

## License

MIT
