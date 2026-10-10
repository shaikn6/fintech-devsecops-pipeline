package kubernetes.admission_test

import future.keywords.if
import future.keywords.in

import data.kubernetes.admission

# Shared fixtures for the admission policy tests. All three policy files share
# the kubernetes.admission package, so a "good" object must satisfy all of them.

good_container := {
    "name": "api",
    "image": "ghcr.io/shaikn6/fintech-api:2.4.1",
    "securityContext": {
        "runAsNonRoot": true,
        "runAsUser": 1000,
        "privileged": false,
        "allowPrivilegeEscalation": false,
        "readOnlyRootFilesystem": true,
        "capabilities": {"drop": ["ALL"]},
    },
    "resources": {
        "requests": {"cpu": "100m", "memory": "128Mi"},
        "limits": {"cpu": "500m", "memory": "512Mi"},
    },
}

good_pod := {"request": {
    "kind": {"kind": "Pod"},
    "namespace": "fintech-prod",
    "object": {
        "metadata": {
            "name": "fintech-api",
            "labels": {"app.kubernetes.io/name": "fintech-api"},
            "annotations": {
                "cosign.sigstore.dev/verified": "true",
                "cosign.sigstore.dev/sbom": "true",
            },
        },
        "spec": {"containers": [good_container]},
    },
}}

good_netpol := {"request": {
    "kind": {"kind": "NetworkPolicy"},
    "namespace": "fintech-prod",
    "object": {
        "metadata": {"name": "fintech-api-allow"},
        "spec": {
            "podSelector": {"matchLabels": {"app.kubernetes.io/name": "fintech-api"}},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": [{"ipBlock": {"cidr": "10.0.0.0/16"}}]}],
            "egress": [{"to": [{"ipBlock": {
                "cidr": "0.0.0.0/0",
                "except": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            }}]}],
        },
    },
}}

# Apply JSON patches to a fixture.
patched(obj, patches) := json.patch(obj, patches)

# True when the policy set denies `req` with a message containing `substr`.
denied(req, substr) if {
    some msg in admission.deny with input as req
    contains(msg, substr)
}

allowed(req) if {
    count(admission.deny) == 0 with input as req
}
