package main

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Conftest entrypoint for rendered manifests (e.g. `helm template` output).
# The policies in policies/rego are written against AdmissionReview input, so
# each manifest is wrapped in that shape before they are evaluated. Workloads
# that embed a pod template are evaluated as the Pod they would create.

pod_template_kinds := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

namespace := object.get(object.get(input, "metadata", {}), "namespace", "default")

review := {"request": {
    "kind": {"kind": "Pod"},
    "namespace": namespace,
    "object": input.spec.template,
}} if {
    input.kind in pod_template_kinds
} else := {"request": {
    "kind": {"kind": input.kind},
    "namespace": namespace,
    "object": input,
}}

deny contains msg if {
    data.kubernetes.admission.deny[msg] with input as review
}
