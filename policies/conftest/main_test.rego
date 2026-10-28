package main_test

import future.keywords.if
import future.keywords.in

import data.main

good_template := {
    "metadata": {
        "labels": {"app.kubernetes.io/name": "fintech-api"},
        "annotations": {
            "cosign.sigstore.dev/verified": "true",
            "cosign.sigstore.dev/sbom": "true",
        },
    },
    "spec": {"containers": [{
        "name": "api",
        "image": "ghcr.io/shaikn6/fintech-api:2.4.1",
        "securityContext": {
            "runAsNonRoot": true,
            "runAsUser": 1000,
            "allowPrivilegeEscalation": false,
            "readOnlyRootFilesystem": true,
            "capabilities": {"drop": ["ALL"]},
        },
        "resources": {
            "requests": {"cpu": "100m", "memory": "128Mi"},
            "limits": {"cpu": "500m", "memory": "512Mi"},
        },
    }]},
}

deployment(template) := {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "fintech-api", "namespace": "fintech-prod"},
    "spec": {"template": template},
}

test_compliant_deployment_passes if {
    count(main.deny) == 0 with input as deployment(good_template)
}

test_deployment_pod_template_is_evaluated if {
    bad := json.patch(good_template, [{"op": "add", "path": "/spec/containers/0/securityContext/privileged", "value": true}])
    some msg in main.deny with input as deployment(bad)
    contains(msg, "is privileged")
}

test_network_policy_manifest_is_evaluated if {
    manifest := {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "allow-ingress", "namespace": "fintech-prod"},
        "spec": {"podSelector": {"matchLabels": {"app": "fintech-api"}}, "policyTypes": ["Ingress"]},
    }
    some msg in main.deny with input as manifest
    contains(msg, "must include 'Egress' in policyTypes")
}

test_compliant_network_policy_manifest_passes if {
    manifest := {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "allow-ingress", "namespace": "fintech-prod"},
        "spec": {"podSelector": {"matchLabels": {"app": "fintech-api"}}, "policyTypes": ["Ingress", "Egress"]},
    }
    count(main.deny) == 0 with input as manifest
}

test_unrelated_kinds_pass if {
    count(main.deny) == 0 with input as {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "fintech-api"}}
}
