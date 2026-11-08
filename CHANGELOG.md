# Changelog

## 0.2.1 (unreleased)

**SECURITY: fixed an IdP bypass present in 0.2.0. Upgrade.**

- **Impact:** in 0.2.0, any issuer registered in `trusted_issuers` (via
  `delcred trust-add` or `policy.yaml`) could sign a token with
  `kind: delegation` and `typ: at+jwt`. `delcred verify` / `verify_delegation_token`
  accepted it as a delegation without any policy grant, so a holder of the
  IdP's signing key (or a compromised IdP) could mint delegations around your
  policy. An external IdP's `kind: agent` tokens were also accepted as actor
  tokens in `exchange`.
- **Affected:** delcred 0.2.0 deployments that configured at least one trusted
  external IdP. Setups using only the local issuer (no `trusted_issuers`) are
  not affected.
- **Fix:** delegation tokens and actor (agent) tokens are accepted only from the
  local issuer (`iss: delcred`). Trusted IdPs vouch for users (subject tokens)
  only. Regression test: `tests/test_trust.py::test_idp_bypass_regression_0_2_0`.
- Also: `delegate(user=, agent=)` must now match the presented tokens (they were
  silently ignored); the HTTP server returns 400 for a non-object JSON body.
