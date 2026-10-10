package kubernetes.admission

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# DENY: containers running as root (runAsUser == 0)
deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    sc := container.securityContext
    sc.runAsUser == 0
    msg := sprintf(
        "Container '%v' must not run as root (runAsUser=0). Set runAsNonRoot=true and runAsUser >= 1000.",
        [container.name]
    )
}

deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    sc := container.securityContext
    sc.runAsNonRoot == false
    msg := sprintf(
        "Container '%v' has runAsNonRoot=false. This is forbidden by fintech security policy.",
        [container.name]
    )
}

deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.securityContext.runAsNonRoot
    not container.securityContext.runAsUser
    not input.request.object.spec.securityContext.runAsNonRoot
    not input.request.object.spec.securityContext.runAsUser
    msg := sprintf(
        "Container '%v' has no runAsNonRoot or runAsUser set. Explicit non-root context is required.",
        [container.name]
    )
}

# DENY: privileged containers
deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf(
        "Container '%v' is privileged. Privileged containers are forbidden.",
        [container.name]
    )
}

deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.initContainers[_]
    container.securityContext.privileged == true
    msg := sprintf(
        "Init container '%v' is privileged. Privileged containers are forbidden.",
        [container.name]
    )
}

# DENY: allowPrivilegeEscalation not explicitly false
deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf(
        "Container '%v' must set allowPrivilegeEscalation=false.",
        [container.name]
    )
}

# DENY: missing CPU limit
deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.resources.limits.cpu
    msg := sprintf(
        "Container '%v' is missing CPU limit. Resource limits are required for all containers.",
        [container.name]
    )
}

# DENY: missing memory limit
deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf(
        "Container '%v' is missing memory limit. Resource limits are required for all containers.",
        [container.name]
    )
}

# DENY: missing CPU request
deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.resources.requests.cpu
    msg := sprintf(
        "Container '%v' is missing CPU request.",
        [container.name]
    )
}

# DENY: missing memory request
deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.resources.requests.memory
    msg := sprintf(
        "Container '%v' is missing memory request.",
        [container.name]
    )
}

# DENY: read-only root filesystem not set
deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem == true
    msg := sprintf(
        "Container '%v' must set readOnlyRootFilesystem=true.",
        [container.name]
    )
}

# DENY: capabilities not dropped
deny contains msg if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not "ALL" in object.get(container, ["securityContext", "capabilities", "drop"], [])
    msg := sprintf(
        "Container '%v' must drop ALL capabilities. Add capabilities.drop=['ALL'] to securityContext.",
        [container.name]
    )
}
