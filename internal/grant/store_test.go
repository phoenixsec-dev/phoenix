package grant

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestTransitionsAndIdempotency(t *testing.T) {
	e := newEnv(t)
	r := e.create("vector", "infra/b2/app-key")
	if r.Status != StatusPending || r.ExpiresAt != t0.Add(DefaultRequestTTL) {
		t.Fatalf("new request: %+v", r)
	}

	// The requester can never decide its own request.
	_, _, err := e.s.Approve(ApproveInput{RequestID: r.ID, Approver: "vector"})
	wantCode(t, err, CodeSelfApproval)
	_, err = e.s.Deny(DenyInput{RequestID: r.ID, Denier: "vector"})
	wantCode(t, err, CodeSelfApproval)
	_, _, err = e.s.Approve(ApproveInput{RequestID: "req_nope", Approver: "x"})
	wantCode(t, err, CodeNotFound)

	g := e.approve(r.ID)
	got, _ := e.s.GetRequest(r.ID)
	if got.Status != StatusApproved || got.GrantID != g.ID || got.DecidedBy != "dashboard@10.0.0.9" {
		t.Fatalf("approved request: %+v", got)
	}
	approvedLines := e.sink.count(EventRequestApproved)

	// Same decision, same params: original result, no new transition.
	_, g2, err := e.s.Approve(approveIn(r.ID))
	if err != nil || g2.ID != g.ID {
		t.Fatalf("repeat approve: %v %v", g2.ID, err)
	}
	if e.sink.count(EventRequestApproved) != approvedLines {
		t.Fatal("idempotent repeat wrote a new committed line")
	}
	// Different params or a different decision: 409.
	in := approveIn(r.ID)
	in.TTL = 5 * time.Minute
	_, _, err = e.s.Approve(in)
	wantCode(t, err, CodeNotPending)
	_, err = e.s.Deny(DenyInput{RequestID: r.ID, Denier: "dashboard@x"})
	wantCode(t, err, CodeNotPending)

	// Deny: repeat with same note is idempotent; different note or approve is 409.
	d := e.create("vector", "infra/other")
	if _, err := e.s.Deny(DenyInput{RequestID: d.ID, Denier: "dashboard@x", Note: "no"}); err != nil {
		t.Fatal(err)
	}
	if got, err := e.s.Deny(DenyInput{RequestID: d.ID, Denier: "dashboard@x", Note: "no"}); err != nil || got.Status != StatusDenied {
		t.Fatalf("repeat deny: %v %v", got.Status, err)
	}
	_, err = e.s.Deny(DenyInput{RequestID: d.ID, Denier: "dashboard@x", Note: "changed"})
	wantCode(t, err, CodeNotPending)
	_, _, err = e.s.Approve(approveIn(d.ID))
	wantCode(t, err, CodeNotPending)

	// Pending window edge: one tick before expiry is still pending, at
	// expiry it is expired and can no longer be decided.
	x := e.create("echo", "infra/key")
	e.clock.Set(x.ExpiresAt.Add(-time.Nanosecond))
	if got, _ := e.s.GetRequest(x.ID); got.Status != StatusPending {
		t.Fatalf("1ns before expiry: %s", got.Status)
	}
	e.clock.Set(x.ExpiresAt)
	if got, _ := e.s.GetRequest(x.ID); got.Status != StatusExpired {
		t.Fatalf("at expiry: %s", got.Status)
	}
	_, _, err = e.s.Approve(approveIn(x.ID))
	wantCode(t, err, CodeNotPending)
}

func TestApproveNarrowing(t *testing.T) {
	e := newEnv(t)
	in := bearerIn("vector", "infra/a", "infra/b", "infra/c")
	in.TTL = 2 * time.Hour
	r, _, err := e.s.Create(in)
	if err != nil {
		t.Fatal(err)
	}

	bad := []struct {
		name string
		mod  func(*ApproveInput)
		code Code
	}{
		{"widen path", func(a *ApproveInput) { a.Paths = []string{"infra/a", "infra/z"} }, CodeWideningNotAllowed},
		{"widen ttl", func(a *ApproveInput) { a.TTL = 3 * time.Hour }, CodeWideningNotAllowed},
		{"empty", func(a *ApproveInput) { a.Paths = []string{} }, CodeEmptyGrant},
		{"tiny ttl", func(a *ApproveInput) { a.TTL = time.Second }, CodeInvalidRequest},
	}
	for _, tc := range bad {
		a := approveIn(r.ID)
		tc.mod(&a)
		_, _, err := e.s.Approve(a)
		if CodeOf(err) != tc.code {
			t.Errorf("%s: err = %v, want %s", tc.name, err, tc.code)
		}
	}
	if got, _ := e.s.GetRequest(r.ID); got.Status != StatusPending {
		t.Fatal("rejected approvals must leave the request pending")
	}

	// Narrow to two paths; current MaxTTL (30m) clamps the requested 2h.
	a := approveIn(r.ID)
	a.Paths = []string{"infra/c", "infra/a"}
	a.MaxTTL = 30 * time.Minute
	a.SealedOnly, a.BindSourceIP = false, false
	_, g, err := e.s.Approve(a)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(g.Paths, []string{"infra/a", "infra/c"}) || g.ExpiresAt.Sub(g.CreatedAt) != 30*time.Minute {
		t.Fatalf("grant paths %v ttl %v", g.Paths, g.ExpiresAt.Sub(g.CreatedAt))
	}
	if g.SealedOnly || g.BoundSourceIP != "" || g.AuthMethod != AuthBearer || g.CredentialFP != "fp-vector" {
		t.Fatalf("grant binding fields: %+v", g)
	}

	// Returned values are copies: mutating them does not touch the store.
	g.Paths[0] = "infra/z"
	if again, _ := e.s.GetGrant(g.ID); again.Paths[0] != "infra/a" {
		t.Fatal("caller mutation leaked into the store")
	}
}

func TestLimits(t *testing.T) {
	e := newEnv(t)

	// 3 pending per agent; an identical request is a 200 duplicate even at the cap.
	first := e.create("vector", "ns/a")
	e.clock.Advance(time.Minute)
	e.create("vector", "ns/b")
	e.create("vector", "ns/c")
	dup, created, err := e.s.Create(bearerIn("vector", "ns/a"))
	if err != nil || created || dup.ID != first.ID {
		t.Fatalf("duplicate: %v created=%v err=%v", dup.ID, created, err)
	}
	_, _, err = e.s.Create(bearerIn("vector", "ns/d"))
	wantCode(t, err, CodeTooManyPending)
	var ge *Error
	if !errors.As(err, &ge) || ge.RetryAfter != first.ExpiresAt.Sub(e.clock.Now()) {
		t.Fatalf("retry-after = %v, want time until the oldest pending expires", ge.RetryAfter)
	}

	// 50 pending in total across agents.
	for i := 0; i < 47; i++ {
		e.create(fmt.Sprintf("bulk%02d", i), "ns/a")
	}
	_, _, err = e.s.Create(bearerIn("one-more", "ns/a"))
	wantCode(t, err, CodeTooManyPending)

	// 10 creates per agent per hour, counted from stored records (denied
	// requests and duplicates included / excluded as the plan says).
	e2 := newEnv(t)
	var oldest time.Time
	for i := 0; i < MaxCreatesPerHour; i++ {
		r := e2.create("echo", fmt.Sprintf("ns/p%d", i))
		if i == 0 {
			oldest = r.CreatedAt
		}
		if _, err := e2.s.Deny(DenyInput{RequestID: r.ID, Denier: "dashboard@x"}); err != nil {
			t.Fatal(err)
		}
		e2.clock.Advance(time.Minute)
	}
	_, _, err = e2.s.Create(bearerIn("echo", "ns/new"))
	wantCode(t, err, CodeRateLimited)
	if errors.As(err, &ge); ge.RetryAfter != oldest.Add(time.Hour).Sub(e2.clock.Now()) {
		t.Fatalf("rate-limit retry-after = %v", ge.RetryAfter)
	}
	e2.reopen() // survives restart
	_, _, err = e2.s.Create(bearerIn("echo", "ns/new"))
	wantCode(t, err, CodeRateLimited)
	e2.clock.Set(oldest.Add(time.Hour))
	e2.create("echo", "ns/new")

	// 10 active grants per agent, checked at approval; the request stays pending.
	e3 := newEnv(t)
	for i := 0; i < MaxActiveGrants; i++ {
		in := bearerIn("relay", fmt.Sprintf("ns/g%d", i))
		in.TTL = 8 * time.Hour
		r, _, err := e3.s.Create(in)
		if err != nil {
			t.Fatal(err)
		}
		e3.approve(r.ID)
		e3.clock.Advance(7 * time.Minute) // stay under 10 creates/hour
	}
	r := e3.create("relay", "ns/eleventh")
	_, _, err = e3.s.Approve(approveIn(r.ID))
	wantCode(t, err, CodeGrantLimit)
	if got, _ := e3.s.GetRequest(r.ID); got.Status != StatusPending {
		t.Fatalf("after GRANT_LIMIT request is %s, want pending", got.Status)
	}
}

func TestCooldown(t *testing.T) {
	e := newEnv(t)
	r := e.create("vector", "ns/a", "ns/b")
	if _, err := e.s.Deny(DenyInput{RequestID: r.ID, Denier: "dashboard@x"}); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(3 * time.Minute)

	// Any overlapping path is blocked, with retry-after to the end of the cooldown.
	_, _, err := e.s.Create(bearerIn("vector", "ns/b", "ns/c"))
	wantCode(t, err, CodeRequestCooldown)
	var ge *Error
	if errors.As(err, &ge); ge.RetryAfter != 7*time.Minute {
		t.Fatalf("retry-after = %v, want 7m", ge.RetryAfter)
	}
	// Non-overlapping path and other agents are not blocked.
	e.create("vector", "ns/c")
	e.create("echo", "ns/a")

	// Restart during cooldown: still blocked (derived from stored decided_at).
	e.reopen()
	_, _, err = e.s.Create(bearerIn("vector", "ns/a"))
	wantCode(t, err, CodeRequestCooldown)

	// Exactly 10 minutes after the denial the cooldown is over.
	e.clock.Set(t0.Add(DenyCooldown))
	e.create("vector", "ns/a")
}

func TestMatch(t *testing.T) {
	e := newEnv(t)
	r := e.create("vector", "infra/key", "infra/other")
	g := e.approve(r.ID)

	nm := func(c Caller, path, action string) MatchResult { return e.s.Match(c, path, action) }
	ok := bearerCaller("vector")
	if m := nm(ok, "infra/key", ActionReadValue); m.Grant == nil || m.Grant.ID != g.ID {
		t.Fatalf("matching caller: %+v", m)
	}
	misses := map[string]struct {
		c      Caller
		path   string
		action string
	}{
		"other path":      {ok, "infra/nope", ActionReadValue},
		"other action":    {ok, "infra/key", "write"},
		"other agent":     {bearerCaller("echo"), "infra/key", ActionReadValue},
		"wrong token fp":  {Caller{Agent: "vector", SourceIP: "10.0.0.5", AuthMethod: AuthBearer, CredentialFP: "fp-rotated"}, "infra/key", ActionReadValue},
		"wrong ip":        {Caller{Agent: "vector", SourceIP: "10.0.0.6", AuthMethod: AuthBearer, CredentialFP: "fp-vector"}, "infra/key", ActionReadValue},
		"mtls not bearer": {Caller{Agent: "vector", SourceIP: "10.0.0.5", AuthMethod: AuthMTLS, CredentialFP: "fp-vector"}, "infra/key", ActionReadValue},
		"session":         {Caller{Agent: "vector", SourceIP: "10.0.0.5", AuthMethod: "session", CredentialFP: "fp-vector"}, "infra/key", ActionReadValue},
	}
	for name, tc := range misses {
		if m := nm(tc.c, tc.path, tc.action); m.Grant != nil || m.Reason != "" {
			t.Errorf("%s: got %+v, want no grant and no reason", name, m)
		}
	}
	e.setGone("vector", true)
	if m := nm(ok, "infra/key", ActionReadValue); m.Grant != nil {
		t.Fatal("agent removed from ACL still matched")
	}
	e.setGone("vector", false)

	// mTLS binding: same cert fingerprint required; bind_source_ip off allows other IPs.
	in := bearerIn("mtls-agent", "infra/key")
	in.AuthMethod, in.CredentialFP = AuthMTLS, "sha256:cert1"
	mr, _, err := e.s.Create(in)
	if err != nil {
		t.Fatal(err)
	}
	a := approveIn(mr.ID)
	a.BindSourceIP = false
	if _, _, err := e.s.Approve(a); err != nil {
		t.Fatal(err)
	}
	mc := Caller{Agent: "mtls-agent", SourceIP: "10.9.9.9", AuthMethod: AuthMTLS, CredentialFP: "sha256:cert1"}
	if nm(mc, "infra/key", ActionReadValue).Grant == nil {
		t.Fatal("mtls with same cert from another IP (binding off) should match")
	}
	mc.CredentialFP = "sha256:cert2"
	if nm(mc, "infra/key", ActionReadValue).Grant != nil {
		t.Fatal("different cert matched")
	}

	// Expiry at exact clock edges, then the 24h "recently ended" window.
	e.clock.Set(g.ExpiresAt.Add(-time.Nanosecond))
	if nm(ok, "infra/key", ActionReadValue).Grant == nil {
		t.Fatal("1ns before expiry should still match")
	}
	e.clock.Set(g.ExpiresAt)
	if m := nm(ok, "infra/key", ActionReadValue); m.Grant != nil || m.Reason != ReasonGrantExpired {
		t.Fatalf("at expiry: %+v", m)
	}
	e.clock.Set(g.ExpiresAt.Add(EndedLookback))
	if m := nm(ok, "infra/key", ActionReadValue); m.Reason != "" {
		t.Fatalf("24h after expiry reason = %q, want plain denial", m.Reason)
	}
}

func TestShortLivedTokenAndTombstone(t *testing.T) {
	e := newEnv(t)
	tokenIn := func() CreateInput {
		in := bearerIn("kit", "infra/key")
		in.AuthMethod, in.CredentialFP = AuthToken, ""
		return in
	}
	r, _, err := e.s.Create(tokenIn())
	if err != nil {
		t.Fatal(err)
	}
	e.approve(r.ID)

	// Delete the agent: grant revoked, tombstone recorded. Recreate the name.
	e.clock.Advance(time.Minute)
	deletedAt := e.clock.Now()
	if _, err := e.s.DeleteAgent("kit", "admin", "10.0.0.9", nil); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(time.Minute)
	r2, _, err := e.s.Create(tokenIn())
	if err != nil {
		t.Fatal(err)
	}
	g2 := e.approve(r2.ID)
	if !g2.NotBeforeTombstone.Equal(deletedAt) {
		t.Fatalf("not_before_tombstone = %v, want %v", g2.NotBeforeTombstone, deletedAt)
	}

	c := Caller{Agent: "kit", SourceIP: "10.0.0.5", AuthMethod: AuthToken}
	for _, tc := range []struct {
		iat  time.Time
		want bool
	}{
		{time.Time{}, false},                 // no iat
		{deletedAt.Add(-time.Second), false}, // old token from before the delete
		{deletedAt, false},                   // must be strictly after
		{deletedAt.Add(time.Second), true},   // token issued to the recreated agent
	} {
		c.TokenIssuedAt = tc.iat
		if got := e.s.Match(c, "infra/key", ActionReadValue).Grant != nil; got != tc.want {
			t.Errorf("iat %v: match = %v, want %v", tc.iat, got, tc.want)
		}
	}
	// A bearer caller cannot use a token-bound grant.
	if e.s.Match(bearerCaller("kit"), "infra/key", ActionReadValue).Grant != nil {
		t.Fatal("bearer caller used a token-bound grant")
	}
}

func TestRevoke(t *testing.T) {
	e := newEnv(t)
	g := e.approve(e.create("vector", "infra/key").ID)

	// Another agent acting as owner sees NOT_FOUND (no existence oracle).
	_, err := e.s.Revoke(RevokeInput{GrantID: g.ID, By: "echo", OwnerOnly: true})
	wantCode(t, err, CodeNotFound)

	// Revoke at T: a Match at the same instant already fails.
	e.clock.Advance(time.Minute)
	got, err := e.s.Revoke(RevokeInput{GrantID: g.ID, By: "vector", OwnerOnly: true})
	if err != nil || got.State(e.clock.Now()) != GrantRevoked || got.RevokedBy != "vector" {
		t.Fatalf("owner revoke: %+v %v", got, err)
	}
	if m := e.s.Match(bearerCaller("vector"), "infra/key", ActionReadValue); m.Grant != nil || m.Reason != ReasonGrantRevoked {
		t.Fatalf("after revoke: %+v", m)
	}
	// Idempotent: no second committed line.
	if _, err := e.s.Revoke(RevokeInput{GrantID: g.ID, By: "dashboard@x"}); err != nil {
		t.Fatal(err)
	}
	if n := e.sink.count(EventGrantRevoked); n != 1 {
		t.Fatalf("grant.revoked lines = %d, want 1", n)
	}
}

func TestDeleteAgent(t *testing.T) {
	e := newEnv(t)
	g := e.approve(e.create("vector", "infra/a").ID)
	pending := e.create("vector", "infra/b")
	other := e.approve(e.create("echo", "infra/a").ID)

	called := false
	res, err := e.s.DeleteAgent("vector", "admin", "10.0.0.9", func() error { called = true; return nil })
	if err != nil || !called {
		t.Fatalf("delete: %v called=%v", err, called)
	}
	if !slices.Equal(res.RevokedGrants, []string{g.ID}) || !slices.Equal(res.ExpiredRequests, []string{pending.ID}) {
		t.Fatalf("result: %+v", res)
	}
	e.reopen() // durable
	if got, _ := e.s.GetGrant(g.ID); got.RevokedAt.IsZero() {
		t.Fatal("grant not revoked after reload")
	}
	if got, _ := e.s.GetRequest(pending.ID); got.Status != StatusExpired {
		t.Fatalf("pending request is %s", got.Status)
	}
	if got, _ := e.s.GetGrant(other.ID); got.State(e.clock.Now()) != GrantActive {
		t.Fatal("another agent's grant was touched")
	}

	// ACL removal fails: grants stay revoked (fail closed), distinct error.
	g2 := e.approve(e.create("echo", "infra/c").ID)
	_, err = e.s.DeleteAgent("echo", "admin", "", func() error { return errInjected })
	wantCode(t, err, CodeDeleteACLFailed)
	if got, _ := e.s.GetGrant(g2.ID); got.RevokedAt.IsZero() {
		t.Fatal("grant not revoked when ACL removal failed")
	}
}

func TestTickExpiryUsageRetention(t *testing.T) {
	e := newEnv(t)
	r := e.create("vector", "infra/key")
	g := e.approve(r.ID)
	e.s.RecordUse(g.ID)
	e.s.RecordUse(g.ID)
	if v, _ := e.s.GetGrant(g.ID); v.UseCount != 2 {
		t.Fatalf("unsaved use count = %d", v.UseCount)
	}
	e.s.Tick()
	e.reopen()
	if v, _ := e.s.GetGrant(g.ID); v.UseCount != 2 || !v.LastUsedAt.Equal(t0) {
		t.Fatalf("saved usage: %d %v", v.UseCount, v.LastUsedAt)
	}

	// Expiry is recorded once by the tick.
	e.clock.Set(g.ExpiresAt)
	e.s.Tick()
	e.s.Tick()
	if n := e.sink.count(EventGrantExpired); n != 1 {
		t.Fatalf("grant.expired lines = %d, want 1", n)
	}

	// Pending request left over a restart: expired and audited at start.
	p := e.create("echo", "infra/key")
	e.clock.Set(p.ExpiresAt.Add(time.Minute))
	e.reopen()
	if n := e.sink.count(EventRequestExpired); n != 1 {
		t.Fatalf("access_request.expired lines = %d, want 1", n)
	}

	// Retention: 30 days after the end, records are pruned (not a moment before).
	e.clock.Set(p.ExpiresAt.Add(Retention - time.Nanosecond))
	e.s.Tick()
	if _, ok := e.s.GetRequest(p.ID); !ok {
		t.Fatal("expired request pruned before 30 days")
	}
	e.clock.Set(p.ExpiresAt.Add(Retention))
	e.s.Tick()
	if _, ok := e.s.GetGrant(g.ID); ok {
		t.Fatal("grant not pruned after 30 days")
	}
	if _, ok := e.s.GetRequest(r.ID); ok {
		t.Fatal("request not pruned after 30 days")
	}
	if _, ok := e.s.GetRequest(p.ID); ok {
		t.Fatal("expired request not pruned after 30 days")
	}
}

func TestTombstonePrune(t *testing.T) {
	e := newEnv(t)
	if _, err := e.s.DeleteAgent("gone", "admin", "", nil); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(DefaultTombstoneRetention - time.Second)
	e.s.Tick()
	if _, ok := e.s.snapshot().Tombstones["gone"]; !ok {
		t.Fatal("tombstone pruned too early")
	}
	e.clock.Advance(time.Second)
	e.s.Tick()
	if _, ok := e.s.snapshot().Tombstones["gone"]; ok {
		t.Fatal("tombstone kept past retention")
	}
}
