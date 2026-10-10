package kubernetes.admission_test

import future.keywords.if

test_compliant_network_policy_allowed if {
    allowed(good_netpol)
}

test_pod_with_app_label_allowed if {
    req := patched(good_pod, [{"op": "replace", "path": "/request/object/metadata/labels", "value": {"app": "fintech-api"}}])
    allowed(req)
}

test_pod_without_app_label_denied_in_protected_namespace if {
    req := patched(good_pod, [{"op": "replace", "path": "/request/object/metadata/labels", "value": {"team": "payments"}}])
    denied(req, "must have label 'app.kubernetes.io/name' or 'app'")
}

test_pod_without_any_labels_denied_in_protected_namespace if {
    req := patched(good_pod, [{"op": "remove", "path": "/request/object/metadata/labels"}])
    denied(req, "must have label 'app.kubernetes.io/name' or 'app'")
}

test_pod_without_app_label_allowed_outside_protected_namespaces if {
    req := patched(good_pod, [
        {"op": "replace", "path": "/request/object/metadata/labels", "value": {"team": "payments"}},
        {"op": "replace", "path": "/request/namespace", "value": "sandbox"},
    ])
    allowed(req)
}

test_missing_ingress_policy_type_denied if {
    req := patched(good_netpol, [{"op": "replace", "path": "/request/object/spec/policyTypes", "value": ["Egress"]}])
    denied(req, "must include 'Ingress' in policyTypes")
}

test_missing_egress_policy_type_denied if {
    req := patched(good_netpol, [{"op": "replace", "path": "/request/object/spec/policyTypes", "value": ["Ingress"]}])
    denied(req, "must include 'Egress' in policyTypes")
}

test_absent_policy_types_denied if {
    req := patched(good_netpol, [{"op": "remove", "path": "/request/object/spec/policyTypes"}])
    denied(req, "must include 'Ingress' in policyTypes")
    denied(req, "must include 'Egress' in policyTypes")
}

test_empty_pod_selector_denied if {
    req := patched(good_netpol, [{"op": "replace", "path": "/request/object/spec/podSelector", "value": {}}])
    denied(req, "has an empty podSelector")
}

test_empty_pod_selector_allowed_for_default_deny_all if {
    req := patched(good_netpol, [
        {"op": "replace", "path": "/request/object/spec/podSelector", "value": {}},
        {"op": "replace", "path": "/request/object/metadata/name", "value": "default-deny-all"},
        {"op": "remove", "path": "/request/object/spec/ingress"},
        {"op": "remove", "path": "/request/object/spec/egress"},
    ])
    allowed(req)
}

test_match_expressions_selector_allowed if {
    req := patched(good_netpol, [{"op": "replace", "path": "/request/object/spec/podSelector", "value": {"matchExpressions": [{"key": "app", "operator": "Exists"}]}}])
    allowed(req)
}

test_ingress_from_anywhere_denied if {
    req := patched(good_netpol, [{"op": "replace", "path": "/request/object/spec/ingress/0/from/0/ipBlock/cidr", "value": "0.0.0.0/0"}])
    denied(req, "allows ingress from 0.0.0.0/0")
}

test_unrestricted_egress_denied if {
    req := patched(good_netpol, [{"op": "remove", "path": "/request/object/spec/egress/0/to/0/ipBlock/except"}])
    denied(req, "allows unrestricted egress to 0.0.0.0/0")
}

test_network_policy_outside_protected_namespaces_ignored if {
    req := patched(good_netpol, [
        {"op": "replace", "path": "/request/namespace", "value": "sandbox"},
        {"op": "replace", "path": "/request/object/spec/policyTypes", "value": []},
        {"op": "replace", "path": "/request/object/spec/podSelector", "value": {}},
        {"op": "replace", "path": "/request/object/spec/ingress/0/from/0/ipBlock/cidr", "value": "0.0.0.0/0"},
    ])
    allowed(req)
}
