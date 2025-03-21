package kubernetes.admission

import future.keywords.if
import future.keywords.in

protected_namespaces := {
    "fintech-prod",
    "fintech-staging",
    "fintech-monitoring",
}

pod_labels(pod) := pod.metadata.labels

# DENY: Pod in protected namespace has no app label for NetworkPolicy selection
deny[msg] if {
    input.request.kind.kind == "Pod"
    ns := input.request.namespace
    ns in protected_namespaces
    labels := pod_labels(input.request.object)
    not labels["app.kubernetes.io/name"]
    not labels["app"]
    msg := sprintf(
        "Pod in namespace '%v' must have label 'app.kubernetes.io/name' or 'app' for NetworkPolicy selection.",
        [ns]
    )
}

# DENY: NetworkPolicy must specify Ingress policyType
deny[msg] if {
    input.request.kind.kind == "NetworkPolicy"
    ns := input.request.namespace
    ns in protected_namespaces
    policy_types := object.get(input.request.object.spec, "policyTypes", [])
    not "Ingress" in policy_types
    msg := sprintf(
        "NetworkPolicy '%v' in namespace '%v' must include 'Ingress' in policyTypes.",
        [input.request.object.metadata.name, ns]
    )
}

# DENY: NetworkPolicy must specify Egress policyType
deny[msg] if {
    input.request.kind.kind == "NetworkPolicy"
    ns := input.request.namespace
    ns in protected_namespaces
    policy_types := object.get(input.request.object.spec, "policyTypes", [])
    not "Egress" in policy_types
    msg := sprintf(
        "NetworkPolicy '%v' in namespace '%v' must include 'Egress' in policyTypes.",
        [input.request.object.metadata.name, ns]
    )
}

# DENY: empty podSelector on non-default-deny policies
deny[msg] if {
    input.request.kind.kind == "NetworkPolicy"
    ns := input.request.namespace
    ns in protected_namespaces
    input.request.object.metadata.name != "default-deny-all"
    count(object.get(input.request.object.spec.podSelector, "matchLabels", {})) == 0
    count(object.get(input.request.object.spec.podSelector, "matchExpressions", [])) == 0
    msg := sprintf(
        "NetworkPolicy '%v' in namespace '%v' has an empty podSelector (selects all pods). Use explicit selectors or name it 'default-deny-all'.",
        [input.request.object.metadata.name, ns]
    )
}

# DENY: ingress rule allows from 0.0.0.0/0
deny[msg] if {
    input.request.kind.kind == "NetworkPolicy"
    ns := input.request.namespace
    ns in protected_namespaces
    ingress_rule := input.request.object.spec.ingress[_]
    from_rule := ingress_rule.from[_]
    cidr := from_rule.ipBlock.cidr
    cidr == "0.0.0.0/0"
    msg := sprintf(
        "NetworkPolicy '%v' allows ingress from 0.0.0.0/0 (all IPs). Restrict source CIDRs.",
        [input.request.object.metadata.name]
    )
}

# DENY: egress rule allows to 0.0.0.0/0 without RFC1918 exceptions
deny[msg] if {
    input.request.kind.kind == "NetworkPolicy"
    ns := input.request.namespace
    ns in protected_namespaces
    egress_rule := input.request.object.spec.egress[_]
    to_rule := egress_rule.to[_]
    cidr := to_rule.ipBlock.cidr
    cidr == "0.0.0.0/0"
    count(object.get(to_rule.ipBlock, "except", [])) == 0
    msg := sprintf(
        "NetworkPolicy '%v' allows unrestricted egress to 0.0.0.0/0 without exceptions. Add RFC1918 except blocks.",
        [input.request.object.metadata.name]
    )
}
