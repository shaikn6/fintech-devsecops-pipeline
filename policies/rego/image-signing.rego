package kubernetes.admission

import future.keywords.if
import future.keywords.in

# Allowed image registries
allowed_registries := {
    "ghcr.io/shaikn6",
    "123456789012.dkr.ecr.us-east-1.amazonaws.com/fintech",
    "gcr.io/fintech-prod",
}

cosign_verified_annotation := "cosign.sigstore.dev/verified"
sbom_annotation            := "cosign.sigstore.dev/sbom"

# Helper: extract registry prefix from image string
image_registry(image) := registry if {
    parts := split(image, "/")
    count(parts) >= 2
    contains(parts[0], ".")
    registry := concat("/", [parts[0], parts[1]])
} else := "docker.io/library"

# DENY: image from disallowed registry
deny[msg] if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    registry := image_registry(container.image)
    not registry in allowed_registries
    msg := sprintf(
        "Container '%v' uses image '%v' from registry '%v' which is not in the allowlist. Allowed: %v",
        [container.name, container.image, registry, allowed_registries]
    )
}

deny[msg] if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.initContainers[_]
    registry := image_registry(container.image)
    not registry in allowed_registries
    msg := sprintf(
        "Init container '%v' uses image '%v' from registry '%v' which is not in the allowlist.",
        [container.name, container.image, registry]
    )
}

# DENY: image tag is 'latest'
deny[msg] if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    endswith(container.image, ":latest")
    msg := sprintf(
        "Container '%v' uses the 'latest' tag for image '%v'. Pin to a specific digest or version tag.",
        [container.name, container.image]
    )
}

# DENY: image has no tag or digest
deny[msg] if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not contains(container.image, ":")
    not contains(container.image, "@")
    msg := sprintf(
        "Container '%v' image '%v' has no tag or digest. Images must be pinned.",
        [container.name, container.image]
    )
}

# DENY: image not signed — cosign annotation missing or false
deny[msg] if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    annotations := object.get(input.request.object.metadata, "annotations", {})
    verified := object.get(annotations, cosign_verified_annotation, "false")
    verified != "true"
    msg := sprintf(
        "Container '%v' image '%v' has not been verified by Cosign. Ensure images are signed with 'cosign sign' and the policy-controller webhook is enabled.",
        [container.name, container.image]
    )
}

# DENY: no SBOM attestation annotation
deny[msg] if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    annotations := object.get(input.request.object.metadata, "annotations", {})
    not object.get(annotations, sbom_annotation, false)
    msg := sprintf(
        "Container '%v' image '%v' is missing SBOM attestation. Attach an SBOM with 'cosign attest --predicate sbom.json --type spdxjson'.",
        [container.name, container.image]
    )
}
