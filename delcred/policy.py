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

    def still_granted(self, claims: dict) -> tuple[bool, str]:
        """Does the CURRENT policy still allow what this delegation token says?

        The root agent (first delegatee of the user) must still hold a grant
        for ``(user, issuer)`` whose scopes and resources cover the token; a
        sub-delegated agent must still be listed in ``delegate_to`` within
        ``max_depth``. Used by ``verify(check_policy=True)``.
        """
        from .tokens import actor_chain, scopes_of, user_issuer

        user = claims.get("sub")
        actors = actor_chain(claims)
        if not isinstance(user, str) or not actors:
            return False, "token does not name a user and an agent"
        grant = self.grant_for(user, actors[-1], user_issuer(claims))
        if grant is None:
            return False, f"no grant for user {user!r} and agent {actors[-1]!r}"
        missing = scopes_of(claims) - grant.scopes
        if missing:
            return False, f"scope(s) no longer granted: {sorted(missing)}"
        if claims.get("aud") not in grant.resources:
            return False, "resource no longer granted"
        if len(actors) > 1:
            if len(actors) - 1 > min(grant.max_depth, MAX_CHAIN_DEPTH):
                return False, "delegation depth no longer allowed"
            if not set(actors[:-1]) <= grant.delegate_to:
                return False, "sub-agent no longer listed in delegate_to"
        return True, ""

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


_GRANT_KEYS = {
    "user", "agent", "scopes", "resources", "max_ttl", "single_use", "issuer",
    "delegate_to", "max_depth",
}


def _str_list(g: dict, key: str, where: str) -> list[str]:
    raw = g.get(key)
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(x, str) and x for x in raw):
        raise PolicyError(
            f"{where}: '{key}' must be a list of non-empty strings (got {type(raw).__name__}); "
            f"write {key}: [\"a\", \"b\"], not a bare string",
            code="request",
        )
    return list(raw)


def _grant_from(g: object, n: int) -> Grant:
    where = f"policy.yaml grant #{n}"
    if not isinstance(g, dict):
        raise PolicyError(f"{where} must be a mapping", code="request")
    for k in ("user", "agent"):
        if not isinstance(g.get(k), (str, int)) or isinstance(g.get(k), bool) or g.get(k) == "":
            raise PolicyError(f"{where}: '{k}' is required", code="request")
    max_ttl = g.get("max_ttl", MAX_TTL)
    if isinstance(max_ttl, bool) or not isinstance(max_ttl, int) or max_ttl <= 0:
        raise PolicyError(f"{where}: max_ttl must be a positive integer (seconds)", code="request")
    single = g.get("single_use", False)
    if not isinstance(single, bool):
        raise PolicyError(f"{where}: single_use must be true or false", code="request")
    scopes = _str_list(g, "scopes", where)
    for sc in scopes:
        try:
            parse_scope(sc)
        except ValueError as e:
            raise PolicyError(f"{where}: {e}", code="request") from e
        if " " in sc:
            raise PolicyError(f"{where}: scope {sc!r} contains a space", code="request")
    return Grant(
        user=str(g["user"]),
        agent=str(g["agent"]),
        scopes=set(scopes),
        resources=_str_list(g, "resources", where),
        max_ttl=max_ttl,
        single_use=single,
        issuer=str(g.get("issuer") or ISSUER_ID),
        delegate_to=set(_str_list(g, "delegate_to", where)),
        max_depth=_depth(g),
    )


def load(base: Path | None = None) -> Policy:
    """Read ``policy.yaml``. Malformed input raises :class:`PolicyError`
    (fail closed) instead of silently producing a different policy: a bare
    string where a list belongs used to become a set of single characters."""
    p = policy_path(base)
    if not p.exists():
        p.write_text(default_policy())
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, UnicodeDecodeError) as e:
        raise PolicyError(f"policy.yaml is not valid YAML: {type(e).__name__}", code="request") from e
    if not isinstance(data, dict):
        raise PolicyError("policy.yaml must be a mapping with a 'grants' list", code="request")
    raw_grants = data.get("grants") or []
    if not isinstance(raw_grants, list):
        raise PolicyError("'grants' must be a list", code="request")
    grants = [_grant_from(g, i) for i, g in enumerate(raw_grants, start=1)]
    return Policy(
        agents=data.get("agents", {}) or {},
        users=data.get("users", {}) or {},
        grants=grants,
    )


def validate(base: Path | None = None) -> tuple[list[str], list[str]]:
    """Lint ``policy.yaml``: returns ``(errors, warnings)``.

    Errors are what ``load`` refuses. Warnings catch things that load fine but
    are almost always mistakes: misspelled keys, duplicate grants (the FIRST
    wins, later ones are dead), grants with no scopes/resources, wildcard-looking
    scopes, plain-http or trailing-slash resources, agents not declared in
    ``agents:``, and delegation targets without their own grant.
    """
    p = policy_path(base)
    errors: list[str] = []
    warnings: list[str] = []
    try:
        pol = load(base)
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except PolicyError as e:
        return [str(e)], []
    seen: dict[tuple[str, str, str], int] = {}
    declared = set((raw.get("agents") or {}).keys()) if isinstance(raw.get("agents"), dict) else set()
    for n, (g, rg) in enumerate(zip(pol.grants, raw.get("grants") or [], strict=True), start=1):
        w = f"grant #{n} ({g.user} / {g.agent})"
        for k in set(rg) - _GRANT_KEYS:
            hint = " (did you mean 'scopes'?)" if k == "scope" else " (did you mean 'resources'?)" if k == "resource" else ""
            warnings.append(f"{w}: unknown key '{k}' is ignored{hint}")
        key = (g.user, g.agent, g.issuer)
        if key in seen:
            warnings.append(f"{w}: duplicates grant #{seen[key]}; only the first one is ever used")
        seen.setdefault(key, n)
        if not g.scopes:
            warnings.append(f"{w}: no scopes, so it can never mint anything")
        if not g.resources:
            warnings.append(f"{w}: no resources, so it can never mint anything")
        for sc in g.scopes:
            if "*" in sc:
                warnings.append(f"{w}: scope {sc!r} looks like a wildcard; scopes are matched exactly")
        for r in g.resources:
            if r.startswith("http://") and "localhost" not in r and "127.0.0.1" not in r:
                warnings.append(f"{w}: resource {r!r} is plain http")
            if r.endswith("/") and r.count("/") > 3:
                warnings.append(f"{w}: resource {r!r} ends with '/'; matching is exact, clients must send it identically")
            if "#" in r:
                warnings.append(f"{w}: resource {r!r} has a fragment (RFC 8707 forbids it)")
        if declared and g.agent not in declared:
            warnings.append(f"{w}: agent is not listed under 'agents:'")
        if g.delegate_to and g.max_depth == 0:
            warnings.append(f"{w}: delegate_to is set but max_depth is 0")
        if g.max_ttl > MAX_TTL:
            warnings.append(f"{w}: max_ttl {g.max_ttl} exceeds the hard cap {MAX_TTL}; it will be clamped")
    return errors, warnings
