"""Deny-by-default delegation policy (YAML).

.. code-block:: yaml

    agents:
      billing-agent:
        description: "Reads invoices for support copilots"
    users:
      u_123: {}
    grants:
      - user: u_123
        agent: billing-agent
        scopes: ["invoices:read"]
        resources: ["https://api.acme.test/v1"]
        max_ttl: 900          # seconds; capped by the global MAX_TTL anyway
        single_use: false

A grant is the *only* thing that lets an exchange mint a token. No grant →
no token. Requested scopes must be a subset of the grant's scopes; the
requested resource must equal one of the grant's resources (exact match —
no prefix games); the requested TTL is clamped to ``min(grant.max_ttl,
MAX_TTL)``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ._common import MAX_TTL, home


@dataclass
class Grant:
    user: str
    agent: str
    scopes: set[str] = field(default_factory=set)
    resources: list[str] = field(default_factory=list)
    max_ttl: int = MAX_TTL
    single_use: bool = False


@dataclass
class Policy:
    agents: dict = field(default_factory=dict)
    users: dict = field(default_factory=dict)
    grants: list[Grant] = field(default_factory=list)

    def grant_for(self, user: str, agent: str) -> Grant | None:
        for g in self.grants:
            if g.user == user and g.agent == agent:
                return g
        return None

    def check(
        self, user: str, agent: str, scope: str, resource: str, ttl: int
    ) -> Grant:
        """Validate a request against policy. Returns the grant (TTL clamped).

        Raises PolicyError if anything is not permitted.
        """
        grant = self.grant_for(user, agent)
        if grant is None:
            raise PolicyError(
                f"no delegation grant for user={user!r} agent={agent!r} "
                "(deny by default)"
            )
        if not isinstance(scope, str) or not isinstance(resource, str):
            raise PolicyError("scope and resource must be strings")
        wanted = set(scope.split())
        if not wanted:
            # Finding #8: a scope-less delegation is almost certainly a
            # caller bug; fail closed rather than mint a bearer token
            # with no stated purpose.
            raise PolicyError("scope must not be empty")
        unknown = wanted - grant.scopes
        if unknown:
            raise PolicyError(
                f"scope(s) not granted: {sorted(unknown)} "
                f"(grant allows: {sorted(grant.scopes)})"
            )
        if resource not in grant.resources:
            raise PolicyError(
                f"resource {resource!r} not granted (grant allows: {grant.resources})"
            )
        if ttl <= 0:
            raise PolicyError("ttl must be positive")
        return grant

    def effective_ttl(self, grant: Grant, requested_ttl: int) -> int:
        return max(1, min(requested_ttl, grant.max_ttl, MAX_TTL))


class PolicyError(Exception):
    pass


def policy_path(base: Path | None = None) -> Path:
    return (base or home()) / "policy.yaml"


def default_policy() -> str:
    return """# delcred delegation policy — deny by default.
# A grant is the ONLY thing that lets an exchange mint a token.
agents:
  example-agent:
    description: "Replace with your agent id"
users:
  u_example: {}
grants:
  - user: u_example
    agent: example-agent
    scopes: ["invoices:read"]
    resources: ["https://api.example.test/v1"]
    max_ttl: 900
    single_use: false
"""


def load(base: Path | None = None) -> Policy:
    p = policy_path(base)
    if not p.exists():
        p.write_text(default_policy())
    data = yaml.safe_load(p.read_text()) or {}
    grants = []
    for g in data.get("grants", []) or []:
        grants.append(
            Grant(
                user=str(g.get("user", "")),
                agent=str(g.get("agent", "")),
                scopes=set(g.get("scopes", []) or []),
                resources=list(g.get("resources", []) or []),
                max_ttl=int(g.get("max_ttl", MAX_TTL)),
                single_use=bool(g.get("single_use", False)),
            )
        )
    return Policy(
        agents=data.get("agents", {}) or {},
        users=data.get("users", {}) or {},
        grants=grants,
    )
