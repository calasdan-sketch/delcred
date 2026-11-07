// delcred verifier — Node 18+, zero dependencies (node:crypto only).
// Implements spec/VERIFICATION.md. Usage:
//   node verify.mjs ../../vectors/vectors.json     # runs the conformance suite
// Library use:  import { verifyOffline } from "./verify.mjs"
import crypto from "node:crypto";
import fs from "node:fs";

const MAX_TOKEN = 16 * 1024;
const MAX_PROOF = 4096;
const FORBIDDEN = ["jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256", "crit"];
const B64URL = /^[A-Za-z0-9_-]*$/;
const BULLETIN_TYP = "delcred-rev+jwt";

class Reject extends Error {}
const isInt = (v) => typeof v === "number" && Number.isInteger(v);
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const nonEmptyStr = (v) => typeof v === "string" && v.length > 0;

function b64(s) {
  if (!B64URL.test(s)) throw new Reject("segment is not base64url without padding");
  const buf = Buffer.from(s, "base64url");
  if (buf.toString("base64url") !== s) throw new Reject("segment is not canonical base64url");
  return buf;
}
function jsonObj(buf, what) {
  let o;
  try { o = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buf)); }
  catch { throw new Reject(`${what} is not valid UTF-8 JSON`); }
  if (!isObj(o)) throw new Reject(`${what} is not a JSON object`);
  return o;
}
function parseCompact(tok) {
  if (typeof tok !== "string" || tok.length > MAX_TOKEN) throw new Reject("token not a string within the size limit");
  const parts = tok.split(".");
  if (parts.length !== 3 || parts.some((p) => !p)) throw new Reject("not a three-segment compact JWS");
  return {
    header: jsonObj(b64(parts[0]), "header"),
    payload: jsonObj(b64(parts[1]), "payload"),
    input: Buffer.from(parts[0] + "." + parts[1], "ascii"),
    sig: b64(parts[2]),
  };
}
function checkHeader(h, allowJwk = false) {
  if (h.alg !== "EdDSA") throw new Reject("alg not accepted");
  for (const n of FORBIDDEN) {
    if (n === "jwk" && allowJwk) continue;
    if (n in h) throw new Reject(`header parameter ${n} not accepted`);
  }
}
function edVerify(x, input, sig) {
  try {
    const raw = b64(x);
    if (raw.length !== 32 || sig.length !== 64) return false;
    const key = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" });
    return crypto.verify(null, input, key, sig);
  } catch { return false; }
}
function jwkFor(jwks, kid) {
  if (!isObj(jwks) || typeof kid !== "string") return null;
  for (const k of jwks.keys ?? []) {
    if (isObj(k) && k.kid === kid && k.kty === "OKP" && k.crv === "Ed25519" &&
        (k.alg ?? "EdDSA") === "EdDSA" && (k.use ?? "sig") === "sig" && typeof k.x === "string") return k.x;
  }
  return null;
}
function parseScope(s) {
  const parts = s.split(" ").filter(Boolean);
  if (!parts.length) throw new Reject("empty scope");
  for (const p of parts) if (!/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(p)) throw new Reject("invalid scope token");
  return new Set(parts);
}
function actors(claims) {
  const out = [];
  let node = claims.act;
  while (node !== undefined && node !== null) {
    if (!isObj(node) || !nonEmptyStr(node.sub)) return null;
    out.push(node.sub);
    if (out.length > 5) return null;
    node = node.act;
  }
  return out.length ? out : null;
}
const sha256b64 = (s) => crypto.createHash("sha256").update(s, "ascii").digest("base64url");

function normalizeHtu(u) {
  let url;
  try { url = new URL(u); } catch { throw new Reject("htu is not an absolute URL"); }
  const scheme = url.protocol.slice(0, -1).toLowerCase();
  if (!url.hostname) throw new Reject("htu has no host");
  // WHATWG URL already lowercases the host and drops default ports.
  return `${scheme}://${url.host}${url.pathname || "/"}`;
}

export class ReplayCache { constructor() { this.seen = new Set(); } }

function verifyProof(proof, { method, url, accessToken, expectedJkt, now, cache }) {
  if (typeof proof !== "string" || !proof || proof.length > MAX_PROOF) throw new Reject("proof missing or oversized");
  const { header, payload, input, sig } = parseCompact(proof);
  checkHeader(header, true);
  if (header.typ !== "dpop+jwt") throw new Reject("typ");
  const jwk = header.jwk;
  if (!isObj(jwk) || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || "d" in jwk || b64(jwk.x).length !== 32)
    throw new Reject("proof key");
  const jkt = crypto.createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`).digest("base64url");
  if (!edVerify(jwk.x, input, sig)) throw new Reject("proof signature");
  const { jti, htm, htu, iat } = payload;
  if (!(typeof jti === "string" && jti.length > 0 && jti.length <= 256)) throw new Reject("jti");
  if (htm !== method) throw new Reject("htm");
  if (typeof htu !== "string" || normalizeHtu(htu) !== normalizeHtu(url)) throw new Reject("htu");
  if (!isInt(iat)) throw new Reject("iat");
  if (iat < now - 120 || iat > now + 60) throw new Reject("iat window");
  if (accessToken !== undefined) {
    if (typeof payload.ath !== "string" || payload.ath !== sha256b64(accessToken)) throw new Reject("ath");
  }
  if (expectedJkt !== undefined && jkt !== expectedJkt) throw new Reject("jkt");
  const id = `${jkt}/${jti}`;
  if (cache.seen.has(id)) throw new Reject("replay");
  cache.seen.add(id);
}

function checkBulletin(b, jwks, now, maxAge, leeway) {
  const { header, payload: p, input, sig } = parseCompact(b);
  checkHeader(header);
  if (String(header.typ ?? "").toLowerCase() !== BULLETIN_TYP) throw new Reject("bulletin typ");
  const x = jwkFor(jwks, header.kid);
  if (!x || !edVerify(x, input, sig)) throw new Reject("bulletin signature");
  if (p.iss !== "delcred") throw new Reject("bulletin issuer");
  if (!isInt(p.iat) || !isInt(p.exp)) throw new Reject("bulletin times");
  if (p.iat > now + leeway || now - p.iat > maxAge || now > p.exp + leeway) throw new Reject("bulletin stale");
  for (const n of ["jtis", "agents"]) if (!Array.isArray(p[n]) || !p[n].every((i) => typeof i === "string")) throw new Reject(n);
  if (!Array.isArray(p.users) || !p.users.every((u) => isObj(u) && typeof u.sub === "string" && (u.iss === undefined || typeof u.iss === "string")))
    throw new Reject("users");
  return p;
}

export function verifyOffline(token, o) {
  const now = o.now ?? Math.floor(Date.now() / 1000);
  const leeway = o.leeway ?? 60;
  const issuer = o.issuer ?? "delcred";
  const fail = (code, detail = "") => ({ ok: false, code, detail });
  let header, claims, input, sig;
  try { ({ header, payload: claims, input, sig } = parseCompact(token)); checkHeader(header); }
  catch (e) { if (e instanceof Reject) return fail("invalid_token", e.message); throw e; }
  if (!["at+jwt", "application/at+jwt"].includes(String(header.typ ?? "").toLowerCase())) return fail("invalid_token", "typ");
  const x = jwkFor(o.jwks, header.kid);
  if (!x) return fail("invalid_token", "kid not in JWKS");
  if (!edVerify(x, input, sig)) return fail("invalid_token", "signature");
  if (claims.iss !== issuer) return fail("invalid_token", "issuer");
  const { exp, nbf, iat } = claims;
  if (!isInt(exp) || !isInt(nbf) || !isInt(iat)) return fail("invalid_token", "numeric dates");
  if (now > exp + leeway) return fail("expired");
  if (now < nbf - leeway) return fail("not_yet_valid");
  if (claims.kind !== "delegation") return fail("invalid_token", "kind");
  const acts = actors(claims);
  if (!acts || !nonEmptyStr(claims.sub) || !nonEmptyStr(claims.jti)) return fail("invalid_token", "sub/act/jti");
  const chain = claims.chain ?? [];
  if (!Array.isArray(chain) || chain.length !== acts.length - 1 || !chain.every(nonEmptyStr)) return fail("invalid_token", "chain");
  const hasCnf = "cnf" in claims;
  if (hasCnf && !(isObj(claims.cnf) && Object.keys(claims.cnf).length === 1 && nonEmptyStr(claims.cnf.jkt))) return fail("invalid_token", "cnf");
  if (typeof claims.aud !== "string") return fail("invalid_token", "aud");
  if (claims.aud !== o.resource) return fail("wrong_audience");
  if (typeof claims.scope !== "string") return fail("invalid_token", "scope");
  const held = new Set(claims.scope.split(" "));
  if (o.requiredScopes?.length) {
    let need;
    try { need = parseScope(o.requiredScopes.join(" ")); } catch (e) { return fail("insufficient_scope", e.message); }
    const missing = [...need].filter((s) => !held.has(s));
    if (missing.length) return fail("insufficient_scope", "missing " + missing.sort().join(" "));
  }
  if (hasCnf) {
    const d = o.dpop;
    if (!d || !d.proof || d.method == null || d.url == null) return fail("dpop_required");
    try {
      verifyProof(d.proof, { method: d.method, url: d.url, accessToken: token, expectedJkt: claims.cnf.jkt, now, cache: o.cache ?? new ReplayCache() });
    } catch (e) { if (e instanceof Reject) return fail("invalid_dpop_proof", e.message); throw e; }
  }
  if (o.bulletin != null || o.requireBulletin) {
    if (o.bulletin == null) return fail("revocation_data_invalid", "bulletin required");
    let b;
    try { b = checkBulletin(o.bulletin, o.jwks, now, o.bulletinMaxAge ?? 300, leeway); }
    catch (e) { if (e instanceof Reject) return fail("revocation_data_invalid", e.message); throw e; }
    const userIss = claims.user_iss || issuer;
    const hit = [claims.jti, ...chain].some((j) => b.jtis.includes(j)) ||
      acts.some((a) => b.agents.includes(a)) ||
      b.users.some((u) => u.sub === claims.sub && (!u.iss || u.iss === userIss));
    if (hit) return fail("revoked");
  }
  return { ok: true, code: "ok", claims };
}

// ---- conformance runner -----------------------------------------------------
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const doc = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  let bad = 0;
  const t0 = process.hrtime.bigint();
  for (const c of doc.cases) {
    const r = c.request, cache = new ReplayCache(), got = [];
    for (let i = 0; i < r.repeat; i++) {
      got.push(verifyOffline(c.token, {
        jwks: doc.jwks, resource: r.resource, requiredScopes: r.required_scopes, now: r.now, leeway: doc.leeway_seconds,
        bulletin: r.bulletin, bulletinMaxAge: doc.bulletin_max_age_seconds, requireBulletin: r.require_bulletin, dpop: r.dpop, cache,
      }).code);
    }
    if (JSON.stringify(got) !== JSON.stringify(c.expect)) { bad++; console.log(`FAIL ${c.name}: expected ${c.expect} got ${got}`); }
  }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  console.log(`node: ${doc.cases.length - bad}/${doc.cases.length} vectors pass (${ms.toFixed(1)} ms)`);
  process.exit(bad ? 1 : 0);
}
