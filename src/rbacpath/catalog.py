"""Every rule's text, the finding type, and the scoring.

Keeping the wording of all rules in one file means a report, the README and the
tests cannot drift apart: they cite the same ids and the same severities.
"""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_RANK = {"error": 3, "warn": 2, "info": 1}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    rationale: str
    fix: str


@dataclass
class Finding:
    id: str
    message: str
    evidence: str
    identity: str | None = None
    location: str | None = None

    @property
    def rule(self) -> Rule:
        return RULES[self.id]

    @property
    def severity(self) -> str:
        return self.rule.severity

    @property
    def title(self) -> str:
        return self.rule.title


def R(id_, title, severity, rationale, fix) -> tuple[str, Rule]:  # noqa: N802 - compact table
    return id_, Rule(id_, title, severity, rationale, fix)


RULES: dict[str, Rule] = dict(
    [
        R(
            "CAP001",
            "Identity holds cluster-admin rules",
            "info",
            "Wildcard verbs on wildcard resources in every API group is the "
            "cluster-admin shape. Platform service accounts hold it legitimately, so "
            "this is context: what matters is who else can reach this identity.",
            "Confirm the identity needs cluster-wide authority; prefer a namespaced "
            "Role for anything narrower.",
        ),
        R(
            "CAP002",
            "Reads secrets across the whole cluster",
            "error",
            "A cluster-wide get or list on secrets yields every ServiceAccount token "
            "in every namespace, which is cluster-admin by impersonation once a "
            "powerful token is among them.",
            "Scope secret access to the namespace that needs it, and bind with a "
            "RoleBinding rather than a ClusterRoleBinding.",
        ),
        R(
            "CAP003",
            "Reads secrets in a namespace",
            "warn",
            "Secrets in a namespace include the tokens of the ServiceAccounts that "
            "run there, so reading them is a route to acting as those workloads.",
            "Use resourceNames to name the secrets the workload actually needs, or "
            "switch to projected, audience-bound tokens.",
        ),
        R(
            "CAP004",
            "Creates pods in a namespace",
            "warn",
            "Anyone who can create a pod in a namespace can mount every secret in "
            "that namespace, including other ServiceAccounts' tokens, and can often "
            "reach the node through a privileged or hostPath pod.",
            "Remove pod-create from application identities; deploy through a "
            "controller with a dedicated, audited ServiceAccount.",
        ),
        R(
            "CAP005",
            "Creates workload controllers in a namespace",
            "warn",
            "Creating a Deployment, DaemonSet, StatefulSet or Job is pod creation "
            "with extra steps: the controller's pods inherit the pod template the "
            "caller writes, including mounts and security context.",
            "Gate workload creation behind a pipeline identity and admit only signed "
            "images with a restricted security context.",
        ),
        R(
            "CAP006",
            "Creates RoleBindings in a namespace",
            "error",
            "A RoleBinding can point at any ClusterRole, including cluster-admin. "
            "Whoever can create one in a namespace can grant themselves full control "
            "of that namespace, and can bind identities that other workloads trust.",
            "Restrict rolebinding creation to the platform team; the built-in "
            "`bind` and `escalate` verbs exist so delegation can be narrower.",
        ),
        R(
            "CAP007",
            "Creates ClusterRoleBindings",
            "error",
            "A ClusterRoleBinding to cluster-admin is a one-object path to full "
            "cluster control, and the creator chooses both the role and the subject.",
            "Hold this verb only by break-glass automation that is itself audited.",
        ),
        R(
            "CAP008",
            "Holds bind or escalate on roles",
            "error",
            "`bind` lets an identity attach an existing role to a subject; "
            "`escalate` lets it edit a role's rules beyond its own permissions. "
            "Either is privilege escalation by design.",
            "Grant `bind` only with a resourceNames list naming the roles that may "
            "be delegated.",
        ),
        R(
            "CAP009",
            "Impersonates users, groups or ServiceAccounts",
            "error",
            "Impersonation makes the API server evaluate requests as the target, so "
            "the impersonator inherits every permission that identity has, including "
            "cluster-admin.",
            "Remove impersonation outside break-glass; when it is needed, scope it "
            "with resourceNames to specific identities.",
        ),
        R(
            "CAP010",
            "Mints ServiceAccount tokens",
            "warn",
            "The serviceaccounts/token subresource issues a token for any "
            "ServiceAccount in reach, which is a direct route to that identity's "
            "permissions without ever reading a secret.",
            "Keep token creation with the controller that runs the workload, and "
            "prefer short-lived projected tokens.",
        ),
        R(
            "CAP011",
            "Reaches the kubelet API through nodes/proxy",
            "error",
            "nodes/proxy routes to the kubelet on each node, whose API can execute "
            "commands in any container on that node and read their mounted tokens.",
            "Remove nodes/proxy from all non-system identities; it has no "
            "application use case.",
        ),
        R(
            "CAP012",
            "Executes into pods in a namespace",
            "warn",
            "pods/exec runs commands inside a running container, which exposes that "
            "pod's mounted ServiceAccount token and any secret it can read.",
            "Restrict exec to on-call break-glass, and audit it through the API "
            "server's audit log.",
        ),
        R(
            "PATH001",
            "Escalation to cluster-admin through role binding",
            "error",
            "An identity that can create bindings, or bind/escalate roles, can attach "
            "cluster-admin to itself or to an identity it controls. No other "
            "permission is needed.",
            "Remove binding creation from the identity and delegate a narrow role "
            "with resourceNames instead.",
        ),
        R(
            "PATH002",
            "Escalation to cluster-admin through impersonation",
            "error",
            "Impersonating a cluster-admin subject makes every subsequent request "
            "succeed as that subject, so the impersonator is cluster-admin without "
            "holding a single workload permission.",
            "Remove the impersonate verb and audit who holds it today.",
        ),
        R(
            "PATH003",
            "Cluster-wide secret read yields ServiceAccount tokens",
            "error",
            "Reading secrets cluster-wide exposes the tokens of every ServiceAccount, "
            "including any bound to cluster-admin. The path needs no exploit, only a "
            "get on the secret.",
            "Scope secret reads to a namespace and rotate any token that was readable.",
        ),
        R(
            "PATH004",
            "Pod creation in a namespace reaches its secrets",
            "warn",
            "A created pod can mount any secret in its namespace, so pod-create is "
            "equivalent to reading every secret there even without a get verb.",
            "Remove pod-create from application identities and admit only restricted "
            "pod security profiles.",
        ),
        R(
            "PATH005",
            "Node access through the kubelet API",
            "error",
            "nodes/proxy reaches a kubelet that can exec into any container on the "
            "node, and every pod's token is mounted there.",
            "Remove nodes/proxy and require authentication and authorisation on the "
            "kubelet itself.",
        ),
        R(
            "W001",
            "Container runs privileged",
            "error",
            "A privileged container has all capabilities and unrestricted device "
            "access; it can usually mount the node's filesystem and leave the "
            "container boundary entirely.",
            "Set privileged: false and add only the specific capabilities needed.",
        ),
        R(
            "W002",
            "Pod mounts a host path",
            "error",
            "A hostPath volume exposes node files to the container. A writable mount "
            "of a sensitive path is node compromise, and the node holds every pod's "
            "token.",
            "Remove hostPath volumes; use a CSI driver or an explicit, read-only "
            "projected volume where a file is genuinely required.",
        ),
        R(
            "W003",
            "Pod shares a host namespace",
            "warn",
            "hostPID, hostIPC or hostNetwork places the container in the node's "
            "namespace, which exposes other processes or the node's network stack.",
            "Disable host namespaces; a node-level agent that needs them belongs in "
            "its own audited namespace.",
        ),
        R(
            "W004",
            "Container runs as root",
            "warn",
            "An explicit runAsUser: 0, or runAsNonRoot: false, keeps the process as "
            "root inside the container, which turns any write primitive into a "
            "broader one.",
            "Set runAsNonRoot: true with a numeric runAsUser.",
        ),
        R(
            "W005",
            "Privilege escalation is permitted",
            "warn",
            "allowPrivilegeEscalation: true lets a process gain more privilege than "
            "its parent through setuid or file capabilities.",
            "Set allowPrivilegeEscalation: false.",
        ),
        R(
            "W006",
            "Container adds capabilities",
            "warn",
            "Added Linux capabilities widen the container's kernel surface; "
            "SYS_ADMIN in particular is close to privileged in effect.",
            "Drop ALL and add back only what the workload demonstrates a need for.",
        ),
        R(
            "W007",
            "Pod automounts its ServiceAccount token",
            "info",
            "A mounted token is readable by anything that compromises the container. "
            "Workloads that never call the API do not need one.",
            "Set automountServiceAccountToken: false unless the workload talks to "
            "the API server.",
        ),
        R(
            "W008",
            "Image reference is mutable",
            "info",
            "A tag such as :latest, or a tag without a digest, can resolve to "
            "different bytes on the next pull, so what was reviewed is not "
            "necessarily what runs.",
            "Pin images by digest.",
        ),
    ]
)


@dataclass(frozen=True)
class Summary:
    counts: dict[str, int]
    score: int
    band: str


def summarise(findings: list[Finding]) -> Summary:
    counts = {"error": 0, "warn": 0, "info": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    score = counts["error"] * 10 + counts["warn"] * 3 + counts["info"]
    if counts["error"]:
        band = "high-risk"
    elif counts["warn"]:
        band = "review"
    else:
        band = "clean"
    return Summary(counts=counts, score=score, band=band)
