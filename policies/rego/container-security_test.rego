package kubernetes.admission_test

import future.keywords.if

c := "/request/object/spec/containers/0"

test_compliant_pod_allowed if {
    allowed(good_pod)
}

test_non_pod_kinds_ignored if {
    allowed({"request": {"kind": {"kind": "ConfigMap"}, "namespace": "fintech-prod", "object": {"metadata": {"name": "x"}}}})
}

test_run_as_root_uid_denied if {
    req := patched(good_pod, [{"op": "replace", "path": concat("", [c, "/securityContext/runAsUser"]), "value": 0}])
    denied(req, "must not run as root")
}

test_non_root_uid_allowed if {
    req := patched(good_pod, [{"op": "replace", "path": concat("", [c, "/securityContext/runAsUser"]), "value": 65534}])
    allowed(req)
}

test_run_as_non_root_without_uid_allowed if {
    req := patched(good_pod, [{"op": "remove", "path": concat("", [c, "/securityContext/runAsUser"])}])
    allowed(req)
}

test_run_as_non_root_false_denied if {
    req := patched(good_pod, [{"op": "replace", "path": concat("", [c, "/securityContext/runAsNonRoot"]), "value": false}])
    denied(req, "has runAsNonRoot=false")
}

test_uid_without_run_as_non_root_allowed if {
    req := patched(good_pod, [{"op": "remove", "path": concat("", [c, "/securityContext/runAsNonRoot"])}])
    allowed(req)
}

test_missing_non_root_context_denied if {
    req := patched(good_pod, [
        {"op": "remove", "path": concat("", [c, "/securityContext/runAsNonRoot"])},
        {"op": "remove", "path": concat("", [c, "/securityContext/runAsUser"])},
    ])
    denied(req, "has no runAsNonRoot or runAsUser set")
}

test_pod_level_non_root_context_allowed if {
    req := patched(good_pod, [
        {"op": "remove", "path": concat("", [c, "/securityContext/runAsNonRoot"])},
        {"op": "remove", "path": concat("", [c, "/securityContext/runAsUser"])},
        {"op": "add", "path": "/request/object/spec/securityContext", "value": {"runAsNonRoot": true, "runAsUser": 1000}},
    ])
    allowed(req)
}

test_privileged_container_denied if {
    req := patched(good_pod, [{"op": "replace", "path": concat("", [c, "/securityContext/privileged"]), "value": true}])
    denied(req, "Container 'api' is privileged")
}

test_privileged_unset_allowed if {
    req := patched(good_pod, [{"op": "remove", "path": concat("", [c, "/securityContext/privileged"])}])
    allowed(req)
}

test_privileged_init_container_denied if {
    init := patched(good_container, [
        {"op": "replace", "path": "/name", "value": "init"},
        {"op": "replace", "path": "/securityContext/privileged", "value": true},
    ])
    req := patched(good_pod, [{"op": "add", "path": "/request/object/spec/initContainers", "value": [init]}])
    denied(req, "Init container 'init' is privileged")
}

test_unprivileged_init_container_allowed if {
    init := patched(good_container, [{"op": "replace", "path": "/name", "value": "init"}])
    req := patched(good_pod, [{"op": "add", "path": "/request/object/spec/initContainers", "value": [init]}])
    allowed(req)
}

test_privilege_escalation_true_denied if {
    req := patched(good_pod, [{"op": "replace", "path": concat("", [c, "/securityContext/allowPrivilegeEscalation"]), "value": true}])
    denied(req, "must set allowPrivilegeEscalation=false")
}

test_privilege_escalation_unset_denied if {
    req := patched(good_pod, [{"op": "remove", "path": concat("", [c, "/securityContext/allowPrivilegeEscalation"])}])
    denied(req, "must set allowPrivilegeEscalation=false")
}

test_missing_cpu_limit_denied if {
    req := patched(good_pod, [{"op": "remove", "path": concat("", [c, "/resources/limits/cpu"])}])
    denied(req, "missing CPU limit")
}

test_missing_memory_limit_denied if {
    req := patched(good_pod, [{"op": "remove", "path": concat("", [c, "/resources/limits/memory"])}])
    denied(req, "missing memory limit")
}

test_missing_cpu_request_denied if {
    req := patched(good_pod, [{"op": "remove", "path": concat("", [c, "/resources/requests/cpu"])}])
    denied(req, "missing CPU request")
}

test_missing_memory_request_denied if {
    req := patched(good_pod, [{"op": "remove", "path": concat("", [c, "/resources/requests/memory"])}])
    denied(req, "missing memory request")
}

test_writable_root_filesystem_denied if {
    req := patched(good_pod, [{"op": "replace", "path": concat("", [c, "/securityContext/readOnlyRootFilesystem"]), "value": false}])
    denied(req, "must set readOnlyRootFilesystem=true")
}

test_capabilities_not_dropped_denied if {
    req := patched(good_pod, [{"op": "replace", "path": concat("", [c, "/securityContext/capabilities/drop"]), "value": ["NET_RAW"]}])
    denied(req, "must drop ALL capabilities")
}

test_capabilities_drop_all_among_others_allowed if {
    req := patched(good_pod, [{"op": "replace", "path": concat("", [c, "/securityContext/capabilities/drop"]), "value": ["NET_RAW", "ALL"]}])
    allowed(req)
}

test_capabilities_unset_denied if {
    req := patched(good_pod, [{"op": "remove", "path": concat("", [c, "/securityContext/capabilities"])}])
    denied(req, "must drop ALL capabilities")
}

test_violation_in_second_container_denied if {
    sidecar := patched(good_container, [
        {"op": "replace", "path": "/name", "value": "sidecar"},
        {"op": "replace", "path": "/securityContext/privileged", "value": true},
    ])
    req := patched(good_pod, [{"op": "add", "path": "/request/object/spec/containers/-", "value": sidecar}])
    denied(req, "Container 'sidecar' is privileged")
}
