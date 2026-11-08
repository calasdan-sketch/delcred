// delcred verifier in Go — standard library only. Implements spec/VERIFICATION.md.
//
//	go run . ../../vectors/vectors.json     # run the conformance suite
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	maxToken    = 16 * 1024
	maxProof    = 4096
	bulletinTyp = "delcred-rev+jwt"
)

var (
	b64urlRe  = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	scopeRe   = regexp.MustCompile(`^[\x21\x23-\x5b\x5d-\x7e]+$`)
	forbidden = []string{"jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256", "crit"}
)

type obj = map[string]any
type reject struct{ msg string }

func (r reject) Error() string { return r.msg }
func rej(m string) error       { return reject{m} }

func b64(s string) ([]byte, error) {
	if !b64urlRe.MatchString(s) {
		return nil, rej("segment is not base64url without padding")
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

const (
	maxSafeInt   = 1<<53 - 1
	maxJSONDepth = 32
)

// strictScan rejects duplicate object members and nesting deeper than maxJSONDepth
// (encoding/json would silently keep the last duplicate).
func strictScan(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		isObj   bool
		expKey  bool
		members map[string]bool
	}
	var stack []frame
	for {
		t, err := dec.Token()
		if err != nil {
			return true // io.EOF or a syntax error: the real decode reports it
		}
		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			if _, isDelim := t.(json.Delim); !isDelim && top.isObj && top.expKey {
				k, ok := t.(string)
				if !ok {
					return true
				}
				if top.members[k] {
					return false
				}
				top.members[k] = true
				top.expKey = false
				continue
			}
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				if len(stack) >= maxJSONDepth {
					return false
				}
				stack = append(stack, frame{isObj: d == '{', expKey: d == '{', members: map[string]bool{}})
				continue
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		}
		// a value finished: the next token in an object is a key again
		if len(stack) > 0 && stack[len(stack)-1].isObj {
			stack[len(stack)-1].expKey = true
		}
	}
}

func jsonObj(raw []byte, what string) (obj, error) {
	if !strictScan(raw) {
		return nil, rej(what + " has a duplicate member or is nested too deeply")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, rej(what + " is not JSON")
	}
	if dec.More() {
		return nil, rej(what + " has trailing data")
	}
	o, ok := v.(obj)
	if !ok {
		return nil, rej(what + " is not an object")
	}
	return o, nil
}

type compact struct {
	header, payload obj
	input, sig      []byte
}

func parseCompact(tok string) (*compact, error) {
	if len(tok) > maxToken {
		return nil, rej("token too large")
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, rej("not a three-segment compact JWS")
	}
	hb, err := b64(parts[0])
	if err != nil {
		return nil, err
	}
	pb, err := b64(parts[1])
	if err != nil {
		return nil, err
	}
	sg, err := b64(parts[2])
	if err != nil {
		return nil, err
	}
	h, err := jsonObj(hb, "header")
	if err != nil {
		return nil, err
	}
	p, err := jsonObj(pb, "payload")
	if err != nil {
		return nil, err
	}
	return &compact{h, p, []byte(parts[0] + "." + parts[1]), sg}, nil
}

func checkHeader(h obj, allowJWK bool) error {
	if h["alg"] != "EdDSA" {
		return rej("alg not accepted")
	}
	for _, n := range forbidden {
		if n == "jwk" && allowJWK {
			continue
		}
		if _, ok := h[n]; ok {
			return rej("header parameter " + n + " not accepted")
		}
	}
	return nil
}

func edVerify(x string, input, sig []byte) bool {
	raw, err := b64(x)
	if err != nil || len(raw) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(raw), input, sig)
}

func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil || strings.ContainsAny(n.String(), ".eE") || i > maxSafeInt || i < -maxSafeInt {
		return 0, false
	}
	return i, true
}

func str(v any) (string, bool) { s, ok := v.(string); return s, ok }
func nonEmpty(v any) bool      { s, ok := v.(string); return ok && s != "" }

func jwkFor(jwks obj, kid any) (string, bool) {
	k, ok := kid.(string)
	if !ok {
		return "", false
	}
	keys, _ := jwks["keys"].([]any)
	for _, e := range keys {
		m, ok := e.(obj)
		if !ok || m["kid"] != k || m["kty"] != "OKP" || m["crv"] != "Ed25519" {
			continue
		}
		if a, has := m["alg"]; has && a != "EdDSA" {
			continue
		}
		if u, has := m["use"]; has && u != "sig" {
			continue
		}
		if x, ok := m["x"].(string); ok {
			return x, true
		}
	}
	return "", false
}

func actors(claims obj) []string {
	var out []string
	node := claims["act"]
	for node != nil {
		m, ok := node.(obj)
		if !ok || !nonEmpty(m["sub"]) {
			return nil
		}
		out = append(out, m["sub"].(string))
		if len(out) > 5 {
			return nil
		}
		node = m["act"]
	}
	return out
}

func sha256b64(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func normalizeHTU(u string) (string, error) {
	p, err := url.Parse(u)
	if err != nil || p.Scheme == "" || p.Hostname() == "" {
		return "", rej("htu is not an absolute URL")
	}
	scheme := strings.ToLower(p.Scheme)
	host := strings.ToLower(p.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := p.Port()
	if port != "" && !((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) {
		host += ":" + port
	}
	path := p.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

type replayCache map[string]bool

type dpopReq struct {
	Proof  string `json:"proof"`
	Method string `json:"method"`
	URL    string `json:"url"`
}

func verifyProof(proof, method, urlStr, accessToken, expectedJkt string, now int64, cache replayCache) error {
	if proof == "" || len(proof) > maxProof {
		return rej("proof missing or oversized")
	}
	c, err := parseCompact(proof)
	if err != nil {
		return err
	}
	if err := checkHeader(c.header, true); err != nil {
		return err
	}
	if c.header["typ"] != "dpop+jwt" {
		return rej("typ")
	}
	jwk, ok := c.header["jwk"].(obj)
	if !ok {
		return rej("jwk")
	}
	x, _ := jwk["x"].(string)
	raw, e := b64(x)
	if _, hasD := jwk["d"]; jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" || x == "" || hasD || e != nil || len(raw) != 32 {
		return rej("proof key")
	}
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
	jkt := base64.RawURLEncoding.EncodeToString(sum[:])
	if !edVerify(x, c.input, c.sig) {
		return rej("proof signature")
	}
	jti, _ := c.payload["jti"].(string)
	if jti == "" || len(jti) > 256 {
		return rej("jti")
	}
	if c.payload["htm"] != method {
		return rej("htm")
	}
	htu, ok := c.payload["htu"].(string)
	if !ok {
		return rej("htu")
	}
	a, err := normalizeHTU(htu)
	if err != nil {
		return err
	}
	b, err := normalizeHTU(urlStr)
	if err != nil {
		return err
	}
	if a != b {
		return rej("htu")
	}
	iat, ok := asInt(c.payload["iat"])
	if !ok {
		return rej("iat")
	}
	if iat < now-120 || iat > now+60 {
		return rej("iat window")
	}
	if ath, _ := c.payload["ath"].(string); ath != sha256b64(accessToken) {
		return rej("ath")
	}
	if jkt != expectedJkt {
		return rej("jkt")
	}
	id := jkt + "/" + jti
	if cache[id] {
		return rej("replay")
	}
	cache[id] = true
	return nil
}

func parseScope(s string) (map[string]bool, error) {
	set := map[string]bool{}
	for _, p := range strings.Split(s, " ") {
		if p == "" {
			continue
		}
		if !scopeRe.MatchString(p) {
			return nil, rej("invalid scope token")
		}
		set[p] = true
	}
	if len(set) == 0 {
		return nil, rej("empty scope")
	}
	return set, nil
}

func contains(list any, s string) bool {
	l, _ := list.([]any)
	for _, e := range l {
		if e == s {
			return true
		}
	}
	return false
}

func checkBulletin(b string, jwks obj, now, maxAge, leeway int64) (obj, error) {
	c, err := parseCompact(b)
	if err != nil {
		return nil, err
	}
	if err := checkHeader(c.header, false); err != nil {
		return nil, err
	}
	if typ, _ := c.header["typ"].(string); strings.ToLower(typ) != bulletinTyp {
		return nil, rej("bulletin typ")
	}
	x, ok := jwkFor(jwks, c.header["kid"])
	if !ok || !edVerify(x, c.input, c.sig) {
		return nil, rej("bulletin signature")
	}
	p := c.payload
	if p["iss"] != "delcred" {
		return nil, rej("bulletin issuer")
	}
	iat, ok1 := asInt(p["iat"])
	exp, ok2 := asInt(p["exp"])
	if !ok1 || !ok2 {
		return nil, rej("bulletin times")
	}
	if iat > now+leeway || now-iat > maxAge || now > exp+leeway {
		return nil, rej("bulletin stale")
	}
	for _, n := range []string{"jtis", "agents"} {
		l, ok := p[n].([]any)
		if !ok {
			return nil, rej(n)
		}
		for _, e := range l {
			if _, ok := e.(string); !ok {
				return nil, rej(n)
			}
		}
	}
	us, ok := p["users"].([]any)
	if !ok {
		return nil, rej("users")
	}
	for _, e := range us {
		m, ok := e.(obj)
		if !ok || !nonEmpty(m["sub"]) {
			return nil, rej("users")
		}
		if i, has := m["iss"]; has {
			if _, ok := i.(string); !ok {
				return nil, rej("users")
			}
		}
	}
	return p, nil
}

type options struct {
	jwks           obj
	resource       string
	requiredScopes []string
	now, leeway    int64
	bulletin       *string
	bulletinMaxAge int64
	requireBull    bool
	dpop           *dpopReq
	cache          replayCache
}

func verifyOffline(token string, o options) (code string) {
	c, err := parseCompact(token)
	if err == nil {
		err = checkHeader(c.header, false)
	}
	if err != nil {
		return "invalid_token"
	}
	if typ, _ := c.header["typ"].(string); typ != "" {
		t := strings.ToLower(typ)
		if t != "at+jwt" && t != "application/at+jwt" {
			return "invalid_token"
		}
	} else {
		return "invalid_token"
	}
	x, ok := jwkFor(o.jwks, c.header["kid"])
	if !ok || !edVerify(x, c.input, c.sig) {
		return "invalid_token"
	}
	cl := c.payload
	if cl["iss"] != "delcred" {
		return "invalid_token"
	}
	exp, e1 := asInt(cl["exp"])
	nbf, e2 := asInt(cl["nbf"])
	_, e3 := asInt(cl["iat"])
	if !e1 || !e2 || !e3 {
		return "invalid_token"
	}
	if o.now > exp+o.leeway {
		return "expired"
	}
	if o.now < nbf-o.leeway {
		return "not_yet_valid"
	}
	if cl["kind"] != "delegation" {
		return "invalid_token"
	}
	acts := actors(cl)
	if acts == nil || !nonEmpty(cl["sub"]) || !nonEmpty(cl["jti"]) {
		return "invalid_token"
	}
	var chain []string
	if raw, has := cl["chain"]; has {
		l, ok := raw.([]any)
		if !ok {
			return "invalid_token"
		}
		for _, e := range l {
			if !nonEmpty(e) {
				return "invalid_token"
			}
			chain = append(chain, e.(string))
		}
	}
	if len(chain) != len(acts)-1 {
		return "invalid_token"
	}
	cnfRaw, hasCnf := cl["cnf"]
	cnfJkt := ""
	if hasCnf {
		m, ok := cnfRaw.(obj)
		if !ok || len(m) != 1 || !nonEmpty(m["jkt"]) {
			return "invalid_token"
		}
		cnfJkt = m["jkt"].(string)
	}
	aud, ok := cl["aud"].(string)
	if !ok {
		return "invalid_token"
	}
	if aud != o.resource {
		return "wrong_audience"
	}
	scope, ok := cl["scope"].(string)
	if !ok {
		return "invalid_token"
	}
	held := map[string]bool{}
	for _, s := range strings.Split(scope, " ") {
		held[s] = true
	}
	if len(o.requiredScopes) > 0 {
		need, err := parseScope(strings.Join(o.requiredScopes, " "))
		if err != nil {
			return "insufficient_scope"
		}
		var missing []string
		for s := range need {
			if !held[s] {
				missing = append(missing, s)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			return "insufficient_scope"
		}
	}
	if hasCnf {
		d := o.dpop
		if d == nil || d.Proof == "" {
			return "dpop_required"
		}
		if err := verifyProof(d.Proof, d.Method, d.URL, token, cnfJkt, o.now, o.cache); err != nil {
			return "invalid_dpop_proof"
		}
	}
	if o.bulletin != nil || o.requireBull {
		if o.bulletin == nil {
			return "revocation_data_invalid"
		}
		b, err := checkBulletin(*o.bulletin, o.jwks, o.now, o.bulletinMaxAge, o.leeway)
		if err != nil {
			return "revocation_data_invalid"
		}
		userIss := "delcred"
		if u, ok := cl["user_iss"].(string); ok && u != "" {
			userIss = u
		}
		hit := contains(b["jtis"], cl["jti"].(string))
		for _, j := range chain {
			hit = hit || contains(b["jtis"], j)
		}
		for _, a := range acts {
			hit = hit || contains(b["agents"], a)
		}
		us, _ := b["users"].([]any)
		for _, e := range us {
			m := e.(obj)
			if m["sub"] == cl["sub"] {
				if i, has := m["iss"].(string); !has || i == "" || i == userIss {
					hit = true
				}
			}
		}
		if hit {
			return "revoked"
		}
	}
	return "ok"
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	var doc struct {
		Leeway     int64 `json:"leeway_seconds"`
		BulletinMA int64 `json:"bulletin_max_age_seconds"`
		JWKS       obj   `json:"jwks"`
		Cases      []struct {
			Name    string   `json:"name"`
			Token   string   `json:"token"`
			Expect  []string `json:"expect"`
			Request struct {
				Resource string   `json:"resource"`
				Scopes   []string `json:"required_scopes"`
				Now      int64    `json:"now"`
				Bulletin *string  `json:"bulletin"`
				ReqBull  bool     `json:"require_bulletin"`
				DPoP     *dpopReq `json:"dpop"`
				Repeat   int      `json:"repeat"`
			} `json:"request"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	bad := 0
	t0 := time.Now()
	for _, c := range doc.Cases {
		cache := replayCache{}
		var got []string
		for i := 0; i < c.Request.Repeat; i++ {
			got = append(got, verifyOffline(c.Token, options{
				jwks: doc.JWKS, resource: c.Request.Resource, requiredScopes: c.Request.Scopes,
				now: c.Request.Now, leeway: doc.Leeway, bulletin: c.Request.Bulletin,
				bulletinMaxAge: doc.BulletinMA, requireBull: c.Request.ReqBull, dpop: c.Request.DPoP, cache: cache,
			}))
		}
		if !reflect.DeepEqual(got, c.Expect) {
			bad++
			fmt.Printf("FAIL %s: expected %v got %v\n", c.Name, c.Expect, got)
		}
	}
	fmt.Printf("go: %d/%d vectors pass (%.1f ms)\n", len(doc.Cases)-bad, len(doc.Cases), float64(time.Since(t0).Microseconds())/1000)
	if bad > 0 {
		os.Exit(1)
	}
}
