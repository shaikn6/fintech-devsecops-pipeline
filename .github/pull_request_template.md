# Pull Request

## Summary
<!-- Describe the change and why it was made -->

## Type of Change
- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Security fix
- [ ] Infrastructure change (Terraform/Kubernetes)
- [ ] CI/CD pipeline change
- [ ] Documentation update

## Related Issues
Closes #

## Security Checklist
- [ ] No secrets or credentials committed
- [ ] All new inputs are validated
- [ ] IAM permissions follow least-privilege principle
- [ ] New container images use minimal base images
- [ ] OPA policies updated for new Kubernetes resources
- [ ] Trivy/Grype scan passes with no new CRITICAL/HIGH findings
- [ ] SBOM generated and attached (if container image changed)
- [ ] Cosign signing configured for new images (if applicable)

## Infrastructure Checklist (if Terraform changed)
- [ ] `terraform fmt` run
- [ ] `terraform validate` passes
- [ ] `terraform plan` reviewed and attached to PR
- [ ] Checkov scan passes (or exceptions documented)
- [ ] S3 state backend encryption verified
- [ ] VPC/security group changes reviewed
- [ ] IAM role changes follow least-privilege

## Kubernetes Checklist (if k8s manifests changed)
- [ ] Resource limits and requests set
- [ ] Network policies updated if new service
- [ ] Pod security context configured
- [ ] Non-root user enforced in Dockerfile
- [ ] Readiness and liveness probes defined
- [ ] Conftest/OPA policies pass

## Testing
- [ ] Unit tests added/updated
- [ ] Tests pass locally (`pytest tests/ -v`)
- [ ] Coverage >= 80%

## Pipeline Validation
- [ ] Security pipeline (ci-security.yml) passes on this branch
- [ ] Deployment pipeline (cd-deploy.yml) tested in dev environment
- [ ] Compliance report reviewed

## Screenshots / Logs
<!-- Attach relevant screenshots, pipeline output, or Terraform plan -->

## Deployment Notes
<!-- Any special deployment steps, rollback considerations, or feature flags -->
