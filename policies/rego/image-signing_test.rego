package kubernetes.admission_test

import future.keywords.if

import data.kubernetes.admission

image_path := "/request/object/spec/containers/0/image"

with_image(image) := patched(good_pod, [{"op": "replace", "path": image_path, "value": image}])

test_image_registry_helper if {
    admission.image_registry("ghcr.io/shaikn6/app:1.0.0") == "ghcr.io/shaikn6"
    admission.image_registry("123456789012.dkr.ecr.us-east-1.amazonaws.com/fintech/fintech-api:2.4.1") == "123456789012.dkr.ecr.us-east-1.amazonaws.com/fintech"
    admission.image_registry("nginx:1.27") == "docker.io/library"
    admission.image_registry("bitnami/redis:7.2") == "docker.io/library"
}

test_allowlisted_registries_allowed if {
    allowed(with_image("ghcr.io/shaikn6/fintech-api:2.4.1"))
    allowed(with_image("123456789012.dkr.ecr.us-east-1.amazonaws.com/fintech/fintech-api:2.4.1"))
    allowed(with_image("gcr.io/fintech-prod/fintech-api:2.4.1"))
}

test_digest_pinned_image_allowed if {
    allowed(with_image("ghcr.io/shaikn6/fintech-api@sha256:0123456789abcdef"))
}

test_disallowed_registry_denied if {
    denied(with_image("quay.io/other/fintech-api:2.4.1"), "from registry 'quay.io/other' which is not in the allowlist")
}

test_docker_hub_image_denied if {
    denied(with_image("nginx:1.27"), "from registry 'docker.io/library' which is not in the allowlist")
}

test_init_container_disallowed_registry_denied if {
    init := patched(good_container, [
        {"op": "replace", "path": "/name", "value": "init"},
        {"op": "replace", "path": "/image", "value": "quay.io/other/init:1.0.0"},
    ])
    req := patched(good_pod, [{"op": "add", "path": "/request/object/spec/initContainers", "value": [init]}])
    denied(req, "Init container 'init' uses image")
}

test_latest_tag_denied if {
    denied(with_image("ghcr.io/shaikn6/fintech-api:latest"), "uses the 'latest' tag")
}

test_untagged_image_denied if {
    denied(with_image("ghcr.io/shaikn6/fintech-api"), "has no tag or digest")
}

test_unsigned_image_denied_when_annotation_missing if {
    req := patched(good_pod, [{"op": "remove", "path": "/request/object/metadata/annotations/cosign.sigstore.dev~1verified"}])
    denied(req, "has not been verified by Cosign")
}

test_unsigned_image_denied_when_annotation_false if {
    req := patched(good_pod, [{"op": "replace", "path": "/request/object/metadata/annotations/cosign.sigstore.dev~1verified", "value": "false"}])
    denied(req, "has not been verified by Cosign")
}

test_missing_sbom_denied if {
    req := patched(good_pod, [{"op": "remove", "path": "/request/object/metadata/annotations/cosign.sigstore.dev~1sbom"}])
    denied(req, "is missing SBOM attestation")
}

test_no_annotations_denies_signature_and_sbom if {
    req := patched(good_pod, [{"op": "remove", "path": "/request/object/metadata/annotations"}])
    denied(req, "has not been verified by Cosign")
    denied(req, "is missing SBOM attestation")
}
