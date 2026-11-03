"""Workload checks.

Only explicit settings are reported. An absent ``securityContext`` is not flagged:
nearly every manifest omits something, and a rule that fires on absence teaches
readers to ignore the report. What is checked is a decision someone wrote down —
``privileged: true``, a hostPath volume, ``runAsUser: 0``.
"""

from __future__ import annotations

from .catalog import Finding
from .model import Cluster, Workload

HOST_NAMESPACES = ("hostPID", "hostIPC", "hostNetwork")


def _containers(pod_spec: dict) -> list[dict]:
    out: list[dict] = []
    for key in ("initContainers", "containers", "ephemeralContainers"):
        value = pod_spec.get(key)
        if isinstance(value, list):
            out.extend(item for item in value if isinstance(item, dict))
    return out


def _image_is_mutable(image: str) -> bool:
    if not image:
        return False
    if "@sha256:" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    return ":" not in last or last.endswith(":latest")


def evaluate(cluster: Cluster) -> list[Finding]:
    findings: list[Finding] = []
    for workload in cluster.workloads:
        spec = workload.pod_spec
        containers = _containers(spec)

        for container in containers:
            name = container.get("name") or "(unnamed container)"
            security = container.get("securityContext")
            security = security if isinstance(security, dict) else {}

            if security.get("privileged") is True:
                findings.append(
                    Finding(
                        "W001",
                        f"{workload.label} runs container {name} privileged",
                        f"containers[{name}].securityContext.privileged = true",
                        location=workload.label,
                    )
                )

            if security.get("runAsUser") == 0 or security.get("runAsNonRoot") is False:
                findings.append(
                    Finding(
                        "W004",
                        f"{workload.label} runs container {name} as root",
                        f"containers[{name}].securityContext = "
                        f"{'runAsUser: 0' if security.get('runAsUser') == 0 else 'runAsNonRoot: false'}",
                        location=workload.label,
                    )
                )

            if security.get("allowPrivilegeEscalation") is True:
                findings.append(
                    Finding(
                        "W005",
                        f"{workload.label} permits privilege escalation in {name}",
                        f"containers[{name}].securityContext.allowPrivilegeEscalation = true",
                        location=workload.label,
                    )
                )

            capabilities = security.get("capabilities")
            added = capabilities.get("add") if isinstance(capabilities, dict) else None
            if isinstance(added, list) and added:
                findings.append(
                    Finding(
                        "W006",
                        f"{workload.label} adds capabilities to {name}",
                        f"containers[{name}].securityContext.capabilities.add = "
                        f"{', '.join(str(c) for c in added)}",
                        location=workload.label,
                    )
                )

            image = container.get("image")
            if isinstance(image, str) and _image_is_mutable(image):
                findings.append(
                    Finding(
                        "W008",
                        f"{workload.label} uses a mutable image reference in {name}",
                        f"containers[{name}].image = {image}",
                        location=workload.label,
                    )
                )

        volumes = spec.get("volumes")
        if isinstance(volumes, list):
            for volume in volumes:
                if not isinstance(volume, dict):
                    continue
                host_path = volume.get("hostPath")
                if isinstance(host_path, dict):
                    path = host_path.get("path", "(no path)")
                    findings.append(
                        Finding(
                            "W002",
                            f"{workload.label} mounts a host path",
                            f"volumes[{volume.get('name')}].hostPath.path = {path}",
                            location=workload.label,
                        )
                    )

        shared = [flag for flag in HOST_NAMESPACES if spec.get(flag) is True]
        if shared:
            findings.append(
                Finding(
                    "W003",
                    f"{workload.label} shares a host namespace",
                    ", ".join(f"{flag} = true" for flag in shared),
                    location=workload.label,
                )
            )

        if spec.get("automountServiceAccountToken") is not False:
            findings.append(
                Finding(
                    "W007",
                    f"{workload.label} automounts the token of {workload.service_account}",
                    "spec.automountServiceAccountToken is not false "
                    f"(serviceAccountName = {workload.service_account})",
                    identity=workload.service_account_identity,
                    location=workload.label,
                )
            )

    return findings
