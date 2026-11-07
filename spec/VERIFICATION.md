# delcred token verification spec (v1)

How a resource server in **any language** verifies a delcred delegation token
using only the issuer's public keys. Reference implementation:
`delcred/offline.py`. Conformance: `spec/vectors/vectors.json` (89 cases);
Node and Go verifiers in `spec/verifiers/` pass all of them.

## Inputs

* `token` — compact JWS string. `jwks` — the issuer JWK Set
  (`GET /.well-known/jwks.json` or `delcred jwks`; it contains the current key
  and any retired key still inside its overlap window).
* `resource` — your canonical API URL. `required_scopes` — scopes this
  operation needs. `now` — Unix seconds. Leeway is 60 s.
* Optional: a signed **revocation bulletin** (`GET /revocations.jwt`), and for
  key-bound tokens the request's `DPoP` proof, HTTP method and full URL.

## Algorithm (first failing step wins; the code is part of the contract)

1. **Structure** — at most 16384 bytes; exactly three non-empty base64url
   segments in canonical form (no `=` padding, trailing bits zero: decode then re-encode must reproduce the text); header and payload are UTF-8 JSON objects.
   Failure: `invalid_token`.
2. **Header** — `alg` is exactly `EdDSA`; none of `jwk jku x5u x5c x5t x5t#S256
   crit` is present; `typ` equals `at+jwt` or `application/at+jwt`
   (case-insensitive); `kid` is present and names a JWKS key
   (`kty=OKP, crv=Ed25519`, `use` absent or `sig`, `alg` absent or `EdDSA`).
   Failure: `invalid_token`.
3. **Signature** — Ed25519 over the ASCII bytes `header_b64 "." payload_b64`;
   signature is 64 bytes. Failure: `invalid_token`.
4. **Claims shape** — `iss == "delcred"`; `exp`, `nbf`, `iat` are JSON integers
   (floats and strings rejected). Failure: `invalid_token`.
5. **Time** — `now > exp + 60` → `expired`; `now < nbf - 60` → `not_yet_valid`.
6. **Delegation shape** — `kind == "delegation"`; `sub`, `jti` non-empty
   strings; `act` is a nested object chain (`{"sub": leaf, "act": {"sub": parent}}`),
   1 to 5 levels; `chain` (optional) is a list of ancestor `jti`s with exactly
   `levels - 1` entries; `cnf`, if present, is exactly `{"jkt": <non-empty string>}`
   (any other confirmation method fails closed); `aud` and `scope` are strings.
   Failure: `invalid_token`.
7. **Audience** — `aud` equals `resource` as an exact string. `wrong_audience`.
8. **Scope** — `scope` is split on ASCII space **only** (not NBSP, tab or any
   other Unicode space); every required scope must be present as a whole
   token. `insufficient_scope`.
9. **Sender constraint** — if `cnf.jkt` is present a DPoP proof is mandatory
   (`dpop_required`), validated per RFC 9449 (`invalid_dpop_proof`):
   header `typ=dpop+jwt`, `alg=EdDSA`, embedded public OKP/Ed25519 `jwk`
   (no private `d`), valid signature, claims `jti` (≤256 chars), `htm` equal to
   the request method, `htu` equal to the request URL after dropping query and
   fragment, lowercasing scheme and host and removing default ports,
   `iat` within `[now-120, now+60]`, `ath` = base64url(SHA-256(token)), the
   RFC 7638 thumbprint of the proof key equals `cnf.jkt`, and the
   `(thumbprint, jti)` pair has not been seen (keep it ≥ 180 s; fail closed if
   your cache is full). A proof sent for an unbound token is ignored.
10. **Revocation** — if you have a bulletin (or your policy requires one):
    it must be an EdDSA JWS with `typ=delcred-rev+jwt`, signed by a JWKS key,
    `iss=delcred`, `iat` ≤ now+60 and no older than your max age (default
    300 s), not past `exp+60`, with list-typed `jtis`, `agents`, `users`;
    otherwise `revocation_data_invalid`. Then the token is `revoked` if its
    `jti` or any `chain` entry is in `jtis`, any agent in the `act` chain is in
    `agents`, or an entry in `users` has `sub` equal to the token's `sub` and
    either no `iss` or `iss` equal to the token's `user_iss` (default `delcred`).
11. Otherwise `ok`.

## What this gives you, and what it does not

* Offline verification needs no network call per request and no shared database.
* Revocation reaches you within the bulletin max age, not "at token expiry".
  Without a bulletin only expiry (default 15 min, max 60) bounds a stolen token.
* The DPoP replay cache is yours to keep; a stateless verifier cannot detect
  proof replay within the 3-minute window.
* Chain depth and attenuation are enforced by the **issuer** when it signs; a
  verifier checks the chain is well-formed and revocation-aware, not that the
  issuer's policy was right.

Regenerate vectors: `delcred vectors --out spec/vectors`. Run: `node
spec/verifiers/node/verify.mjs spec/vectors/vectors.json`, `cd
spec/verifiers/go && go run . ../../vectors/vectors.json`.
