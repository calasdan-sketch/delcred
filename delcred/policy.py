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

from ._common import ISSUER_ID, MAX_CHAIN_DEPTH, MAX_TTL, check_ttl, home, parse_scope


@dataclass
class Grant:
    user: str
    agent: str
    scopes: set[str] = field(default_factory=set)
    resources: list[str] = field(default_factory=list)
    max_ttl: int = MAX_TTL
    single_use: bool = False
    # Which issuer vouches for ``user``. Users are identified by
    # (issuer, user): a grant without ``issuer`` covers only local users,
    # never an IdP user who happens to share the id.
    issuer: str = ISSUER_ID
    # Sub-delegation (agent -> sub-agent). Deny by default: an agent may hand
    # a NARROWER copy of its authority only to agents listed here, at most
    # ``max_depth`` hops deep (hard cap MAX_CHAIN_DEPTH).
    delegate_to: set[str] = field(default_factory=set)
    max_depth: int = 0


@dataclass
class Policy:
    agents: dict = field(default_factory=dict)
    users: dict = field(default_factory=dict)
    grants: list[Grant] = field(default_factory=list)

    def grant_for(self, user: str, agent: str, issuer: str = ISSUER_ID) -> Grant | None:
        for g in self.grants:
            if g.user == user and g.agent == agent and g.issuer == issuer:
                return g
        return None

    def check(
        self,
        user: str,
        agent: str,
        scope: str,
        resource: str,
        ttl: int,
        issuer: str = ISSUER_ID,
    ) -> Grant:
        """Validate a request against policy. Returns the grant (TTL clamped).

        Raises PolicyError if anything is not permitted.
        """
        grant = self.grant_for(user, agent, issuer)
        if grant is None:
            who = user if issuer == ISSUER_ID else f"{user!r}@{issuer}"
            raise PolicyError(
                f"no delegation grant for user={who!r} agent={agent!r} "
                "(deny by default)",
                code="no_grant",
            )
        if not isinstance(scope, str) or not isinstance(resource, str):
            raise PolicyError("scope and resource must be strings")
        try:
            wanted = set(parse_scope(scope))
        except ValueError as e:
            # Empty scopes (finding #8) and non-RFC-6749 characters both fail
            # closed rather than mint a bearer token with an ambiguous purpose.
            raise PolicyError(str(e), code="scope") from e
        unknown = wanted - grant.scopes
        if unknown:
            raise PolicyError(
                f"scope(s) not granted: {sorted(unknown)} "
                f"(grant allows: {sorted(grant.scopes)})",
                code="scope",
            )
        if resource not in grant.resources:
            raise PolicyError(
                f"resource {resource!r} not granted (grant allows: {grant.resources})",
                code="resource",
            )
        try:
            check_ttl(ttl)
        except ValueError as e:
            raise PolicyError(str(e)) from e
        return grant

    def check_delegation(
        self,
        user: str,
        root_agent: str,
        child_agent: str,
        parent_scopes: set[str],
        scope: str,
        resource: str,
        ttl: int,
        depth: int,
        issuer: str = ISSUER_ID,
    ) -> Grant:
        """Policy gate for sub-delegation (attenuation only).

        ``root_agent`` is the first agent the user's grant named; ``depth`` is
        the hop count the new token would have (first sub-agent = 1). The
        child may receive only scopes that are in the parent token AND still
        in the user's current grant, on the same resource.
        """
        grant = self.grant_for(user, root_agent, issuer)
        if grant is None:
            raise PolicyError(
                f"no delegation grant for user={user!r} agent={root_agent!r} (deny by default)",
                code="no_grant",
            )
        if child_agent not in grant.delegate_to:
            raise PolicyError(
                f"agent {root_agent!r} is not allowed to sub-delegate to {child_agent!r} "
                "(grant.delegate_to; deny by default)",
                code="delegation",
            )
        limit = min(grant.max_depth, MAX_CHAIN_DEPTH)
        if depth > limit:
            raise PolicyError(
                f"delegation depth {depth} exceeds the limit {limit} for this grant",
                code="delegation",
            )
        try:
            wanted = set(parse_scope(scope))
        except ValueError as e:
            raise PolicyError(str(e), code="scope") from e
        extra = wanted - parent_scopes
        if extra:
            raise PolicyError(
                f"sub-delegation may only narrow: scope(s) not held by the parent token: {sorted(extra)}",
                code="scope",
            )
        gone = wanted - grant.scopes
        if gone:
            raise PolicyError(
                f"scope(s) no longer granted by policy: {sorted(gone)}", code="scope"
            )
        if resource not in grant.resources:
            raise PolicyError(f"resource {resource!r} not granted", code="resource")
        try:
            check_ttl(ttl)
        except ValueError as e:
            raise PolicyError(str(e)) from e
        return grant

    def effective_ttl(self, grant: Grant, requested_ttl: int) -> int:
        return max(1, min(requested_ttl, grant.max_ttl, MAX_TTL))


class PolicyError(Exception):
    """A delegation request is not permitted.

    ``code`` maps the denial to an OAuth error (used by the RFC 8693
    ``/token`` endpoint): ``no_grant`` → ``invalid_grant``, ``scope`` →
    ``invalid_scope``, ``resource`` → ``invalid_target``, ``request`` →
    ``invalid_request``.
    """

    def __init__(self, message: str, code: str = "request"):
        super().__init__(message)
        self.code = code


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


def _depth(g: dict) -> int:
    """``max_depth`` defaults to 1 when ``delegate_to`` is set, else 0 (no sub-delegation)."""
    raw = g.get("max_depth")
    if raw is None:
        raw = 1 if g.get("delegate_to") else 0
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise PolicyError("max_depth must be a non-negative integer", code="request")
    return min(raw, MAX_CHAIN_DEPTH)


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
                issuer=str(g.get("issuer") or ISSUER_ID),
                delegate_to={str(a) for a in (g.get("delegate_to") or [])},
                max_depth=_depth(g),
            )
        )
    return Policy(
        agents=data.get("agents", {}) or {},
        users=data.get("users", {}) or {},
        grants=grants,
    )
