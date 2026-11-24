package grant

import (
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"testing"
)

// limited files a request for paths and approves it for uses uses.
func (e *env) limited(agent string, uses int64, paths ...string) Grant {
	e.t.Helper()
	in := approveIn(e.create(agent, paths...).ID)
	in.MaxUses = uses
	_, g, err := e.s.Approve(in)
	if err != nil {
		e.t.Fatal(err)
	}
	return g
}

// use does what the API does for one read: match, then spend.
func (e *env) use(agent, path string) error {
	m := e.s.Match(bearerCaller(agent), path, ActionReadValue)
	if m.Grant == nil {
		return newErr(CodeGrantEnded, "%s", m.Reason)
	}
	return e.s.Spend(bearerCaller(agent), ActionReadValue, []SpendItem{{m.Grant.ID, path}}, false)[0]
}

func TestOnceIsOneUsePerPathAndSurvivesRestart(t *testing.T) {
	e := newEnv(t)
	g := e.limited("courier", 1, "infra/a", "infra/b")
	if err := e.use("courier", "infra/a"); err != nil {
		t.Fatal(err)
	}
	e.reopen() // the spent use is on disk, not waiting for Tick
	if err := e.use("courier", "infra/a"); err == nil {
		t.Fatal("infra/a was read twice")
	}
	if m := e.s.Match(bearerCaller("courier"), "infra/a", ActionReadValue); m.Reason != ReasonGrantUsedUp {
		t.Fatalf("reason = %q", m.Reason)
	}
	if err := e.use("courier", "infra/b"); err != nil {
		t.Fatalf("the other path's use was taken too: %v", err)
	}
	e.reopen()
	got, _ := e.s.GetGrant(g.ID)
	if got.State(e.clock.Now()) != GrantUsed || got.UseCount != 2 || e.sink.count(EventGrantUsedUp) == 0 {
		t.Fatalf("grant = %+v state %s", got, got.State(e.clock.Now()))
	}
	// Spent stays spent: not by asking the store directly, not by time.
	for _, err := range e.s.Spend(bearerCaller("courier"), ActionReadValue, []SpendItem{{g.ID, "infra/a"}, {g.ID, "infra/b"}}, false) {
		if CodeOf(err) != CodeGrantUsedUp {
			t.Fatalf("spend on a used grant: %v", err)
		}
	}
	// A replayed approval returns the same spent grant, not a new use.
	in := approveIn(g.RequestID)
	in.MaxUses = 1
	if _, again, err := e.s.Approve(in); err != nil || again.ID != g.ID || again.State(e.clock.Now()) != GrantUsed {
		t.Fatalf("replayed approval: %+v %v", again, err)
	}
	// Without the limit it is a different answer.
	in.MaxUses = 0
	_, _, err := e.s.Approve(in)
	wantCode(t, err, CodeNotPending)
}

func TestUsesExactUnderConcurrency(t *testing.T) {
	e := newEnv(t)
	const uses, callers = 5, 40
	e.limited("courier", uses, "infra/a")
	var ok atomic.Int64
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.use("courier", "infra/a") == nil {
				ok.Add(1)
			}
		}()
	}
	for range 3 {
		wg.Add(1)
		go func() { defer wg.Done(); e.s.Tick() }()
	}
	wg.Wait()
	if ok.Load() != uses {
		t.Fatalf("%d reads allowed, want exactly %d", ok.Load(), uses)
	}
	e.reopen()
	if e.use("courier", "infra/a") == nil {
		t.Fatal("a use came back after a restart")
	}
}

func TestSpendRefusals(t *testing.T) {
	e := newEnv(t)
	g := e.limited("courier", 3, "infra/a")
	item := []SpendItem{{g.ID, "infra/a"}}
	spend := func(c Caller, action, path string) error {
		return e.s.Spend(c, action, []SpendItem{{g.ID, path}}, false)[0]
	}
	other := bearerCaller("courier")
	other.CredentialFP = "fp-new-token"
	elsewhere := bearerCaller("courier")
	elsewhere.SourceIP = "10.0.0.6"
	for name, err := range map[string]error{
		"another agent":  spend(bearerCaller("echo"), ActionReadValue, "infra/a"),
		"replaced token": spend(other, ActionReadValue, "infra/a"),
		"another IP":     spend(elsewhere, ActionReadValue, "infra/a"),
		"another path":   spend(bearerCaller("courier"), ActionReadValue, "infra/b"),
		"another action": spend(bearerCaller("courier"), ActionSSHLogin, "infra/a"),
	} {
		if err == nil {
			t.Errorf("%s could spend the use", name)
		}
	}
	e.setGone("courier", true)
	if e.s.Spend(bearerCaller("courier"), ActionReadValue, item, false)[0] == nil {
		t.Error("a deleted agent could spend")
	}
	e.setGone("courier", false)
	// A revoke between Match and Spend wins.
	m := e.s.Match(bearerCaller("courier"), "infra/a", ActionReadValue)
	if _, err := e.s.Revoke(RevokeInput{GrantID: g.ID, By: "dashboard@x"}); err != nil {
		t.Fatal(err)
	}
	if err := e.s.Spend(bearerCaller("courier"), ActionReadValue, []SpendItem{{m.Grant.ID, "infra/a"}}, false)[0]; SpendReason(err) != ReasonGrantRevoked {
		t.Fatalf("spend after revoke: %v", err)
	}
	if got, _ := e.s.GetGrant(g.ID); got.UseCount != 0 {
		t.Fatalf("refused spends counted: %d", got.UseCount)
	}
}

func TestUsesOrMinutesWhicheverFirst(t *testing.T) {
	e := newEnv(t)
	e.limited("courier", 5, "infra/a")
	e.clock.Advance(DefaultGrantTTL)
	if err := e.use("courier", "infra/a"); err == nil || SpendReason(err) == "" {
		t.Fatalf("used after its time: %v", err)
	}
	if m := e.s.Match(bearerCaller("courier"), "infra/a", ActionReadValue); m.Reason != ReasonGrantExpired {
		t.Fatalf("reason %q", m.Reason)
	}
}

// A use whose save fails is neither spent nor delivered, at whichever step the
// disk gives up, and still there after a restart.
func TestSpendSaveFailure(t *testing.T) {
	for _, step := range []string{"write", "fsync", "rename", "dirsync"} {
		e := newEnv(t)
		g := e.limited("courier", 1, "infra/a")
		e.fs.failOnce(step)
		if err := e.use("courier", "infra/a"); CodeOf(err) != CodeStoreWriteFailed {
			t.Fatalf("%s: %v", step, err)
		}
		if got, _ := e.s.GetGrant(g.ID); got.UsesLeft("infra/a") != 1 {
			t.Fatalf("%s: use lost in memory", step)
		}
		e.reopen()
		if err := e.use("courier", "infra/a"); err != nil {
			t.Fatalf("%s: use lost after a restart: %v", step, err)
		}
	}
}

func TestSpendBatch(t *testing.T) {
	e := newEnv(t)
	g := e.limited("courier", 1, "infra/a", "infra/b")
	items := []SpendItem{{g.ID, "infra/a"}, {g.ID, "infra/a"}, {g.ID, "infra/zzz"}}
	errs := e.s.Spend(bearerCaller("courier"), ActionReadValue, items, true)
	if errs[2] == nil {
		t.Fatal("unknown path spent")
	}
	if got, _ := e.s.GetGrant(g.ID); got.UseCount != 0 {
		t.Fatal("all-or-none spent something")
	}
	// The same path twice in one call is one use.
	errs = e.s.Spend(bearerCaller("courier"), ActionReadValue, items, false)
	if errs[0] != nil || errs[1] != nil || errs[2] == nil {
		t.Fatalf("errs = %v", errs)
	}
	if got, _ := e.s.GetGrant(g.ID); got.UseCount != 1 || got.UsesLeft("infra/b") != 1 {
		t.Fatalf("grant = %+v", got)
	}
}

// Match spends an unlimited grant before one that would run out.
func TestMatchPrefersGrantThatCostsNothing(t *testing.T) {
	e := newEnv(t)
	once := e.limited("courier", 1, "infra/a")
	free := e.approve(e.create("courier", "infra/a", "infra/b").ID)
	if m := e.s.Match(bearerCaller("courier"), "infra/a", ActionReadValue); m.Grant == nil || m.Grant.ID != free.ID {
		t.Fatalf("matched %+v, want %s before %s", m.Grant, free.ID, once.ID)
	}
}

// A login's use is its certificate. The login it opened stays active (so the
// machine keeps it open) and revocable until its time ends.
func TestUsedLoginStaysActiveButSignsNoMore(t *testing.T) {
	e := newEnv(t)
	in := bearerIn("courier", "ssh/build-1")
	in.Action = ActionSSHLogin
	r, _, err := e.s.Create(in)
	if err != nil {
		t.Fatal(err)
	}
	ap := approveIn(r.ID)
	ap.MaxUses = 1
	_, g, err := e.s.Approve(ap)
	if err != nil {
		t.Fatal(err)
	}
	e.reopen() // an unused login grant loads
	if err := e.s.Spend(bearerCaller("courier"), ActionSSHLogin, []SpendItem{{g.ID, "ssh/build-1"}}, false)[0]; err != nil {
		t.Fatal(err)
	}
	e.reopen()
	if m := e.s.Match(bearerCaller("courier"), "ssh/build-1", ActionSSHLogin); m.Grant != nil || m.Reason != ReasonGrantUsedUp {
		t.Fatalf("second certificate: %+v", m)
	}
	got, _ := e.s.GetGrant(g.ID)
	if got.State(e.clock.Now()) != GrantActive {
		t.Fatalf("state = %s", got.State(e.clock.Now()))
	}
	if res, _ := e.s.DeleteAgent("courier", "admin", "", nil); len(res.RevokedGrants) != 1 {
		t.Fatal("deleting the agent must end the open login")
	}
}

// What an older server does with the new file: limited grants are in a map it
// does not know, so it never honours one, and everything else loads as before.
func TestOlderServerNeverHonoursLimitedGrants(t *testing.T) {
	e := newEnv(t)
	once := e.limited("courier", 1, "infra/a")
	open := e.approve(e.create("courier", "infra/b").ID)
	data, err := os.ReadFile(e.path)
	if err != nil {
		t.Fatal(err)
	}
	var old struct { // the state struct of v0.24.0
		Version  int                 `json:"version"`
		Requests map[string]*Request `json:"requests"`
		Grants   map[string]*Grant   `json:"grants"`
	}
	if err := json.Unmarshal(data, &old); err != nil {
		t.Fatal(err)
	}
	if old.Version != 1 || old.Grants[once.ID] != nil || old.Grants[open.ID] == nil || len(old.Requests) != 2 {
		t.Fatalf("older server would see %+v", old)
	}
	// Coming back after the older server saved: the limited grant is gone and
	// its request only says the grant ended.
	saved, _ := json.Marshal(old)
	if err := os.WriteFile(e.path, saved, 0600); err != nil {
		t.Fatal(err)
	}
	e.reopen()
	if h := e.s.Health(); h.Degraded {
		t.Fatalf("degraded: %+v", h)
	}
	if m := e.s.Match(bearerCaller("courier"), "infra/a", ActionReadValue); m.Grant != nil {
		t.Fatal("limited grant came back")
	}
	if m := e.s.Match(bearerCaller("courier"), "infra/b", ActionReadValue); m.Grant == nil {
		t.Fatal("ordinary grant lost")
	}
}

// A grants.json written before uses were counted loads unchanged.
func TestOldGrantsLoadUnchanged(t *testing.T) {
	e := newEnv(t)
	old := `{"version":1,"requests":{},"grants":{"gnt_1":{"id":"gnt_1","request_id":"req_1","agent":"courier","paths":["infra/a"],
	"action":"read_value","sealed_only":true,"auth_method":"bearer","credential_fp":"fp-courier","created_at":"2026-10-20T11:00:00Z",
	"expires_at":"2026-10-20T13:00:00Z","approved_by":"dashboard@x","use_count":7}},"audit_pending":null}`
	if err := os.WriteFile(e.path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	e.reopen()
	for range 3 {
		if err := e.use("courier", "infra/a"); err != nil {
			t.Fatal(err)
		}
	}
	if g, _ := e.s.GetGrant("gnt_1"); g.MaxUses != 0 || g.UsesLeft("infra/a") != -1 || g.UseCount != 7 {
		t.Fatalf("grant = %+v", g)
	}
}

// A use limit where no limit belongs, or the reverse, is a damaged file. It is
// moved aside, never read as "any number of uses".
func TestMisplacedUseLimitIsQuarantined(t *testing.T) {
	e := newEnv(t)
	g := e.limited("courier", 1, "infra/a")
	data, _ := os.ReadFile(e.path)
	var f map[string]any
	json.Unmarshal(data, &f)
	f["grants"] = f["limited_grants"]
	delete(f, "limited_grants")
	bad, _ := json.Marshal(f)
	os.WriteFile(e.path, bad, 0600)
	e.reopen()
	if h := e.s.Health(); !h.Degraded || h.QuarantinedTo == "" {
		t.Fatalf("health = %+v", h)
	}
	if _, ok := e.s.GetGrant(g.ID); ok {
		t.Fatal("damaged grant was loaded")
	}
}

// Counters that cannot be right never give uses back: the file is moved aside.
func TestDamagedCountersAreQuarantined(t *testing.T) {
	for name, damage := range map[string]func(g map[string]any){
		"negative count": func(g map[string]any) { g["path_uses"] = map[string]any{"infra/a": -1} },
		"over the limit": func(g map[string]any) { g["max_uses"] = 5000 },
		"lost counts":    func(g map[string]any) { delete(g, "path_uses") },
		"another path":   func(g map[string]any) { g["path_uses"] = map[string]any{"infra/z": 1} },
		"raised limit":   func(g map[string]any) { g["path_uses"] = map[string]any{"infra/a": 2}; g["use_count"] = 2 },
		"all counts lost": func(g map[string]any) {
			delete(g, "path_uses")
			delete(g, "use_count")
		},
		"no limit at all": func(g map[string]any) { delete(g, "max_uses") },
		"used up unmarked": func(g map[string]any) {
			g["path_uses"] = map[string]any{"infra/a": 1, "infra/b": 1}
			g["use_count"] = 2
		},
	} {
		e := newEnv(t)
		g := e.limited("courier", 1, "infra/a", "infra/b")
		if err := e.use("courier", "infra/a"); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(e.path)
		var f map[string]any
		json.Unmarshal(data, &f)
		damage(f["limited_grants"].(map[string]any)[g.ID].(map[string]any))
		bad, _ := json.Marshal(f)
		os.WriteFile(e.path, bad, 0600)
		e.reopen()
		if h := e.s.Health(); !h.Degraded || h.QuarantinedTo == "" {
			t.Errorf("%s: loaded", name)
		}
	}
}

// After its token is replaced, an agent asking for the same thing gets a new
// request it can use, and the old one stops waiting.
func TestAskingAgainWithANewToken(t *testing.T) {
	e := newEnv(t)
	old := e.create("courier", "infra/a")
	other := e.create("courier", "infra/b")
	in := bearerIn("courier", "infra/a")
	in.CredentialFP = "fp-new"
	fresh, created, err := e.s.Create(in)
	if err != nil || !created || fresh.ID == old.ID {
		t.Fatalf("created=%v %v", created, err)
	}
	for _, id := range []string{old.ID, other.ID} {
		if r, _ := e.s.GetRequest(id); r.Status != StatusExpired || r.Note == "" {
			t.Fatalf("stale request: %+v", r)
		}
	}
	e.reopen()
	e.approve(fresh.ID)
	c := bearerCaller("courier")
	if e.s.Match(c, "infra/a", ActionReadValue).Grant != nil {
		t.Fatal("the old token matches")
	}
	c.CredentialFP = "fp-new"
	if e.s.Match(c, "infra/a", ActionReadValue).Grant == nil {
		t.Fatal("the new token does not match")
	}
}

// The same token given out a second time is another credential.
func TestReissuedTokenIsAnotherCredential(t *testing.T) {
	e := newEnv(t)
	in := bearerIn("courier", "infra/a")
	in.IssueFP = "issue-1"
	r, _, err := e.s.Create(in)
	if err != nil {
		t.Fatal(err)
	}
	e.approve(r.ID)
	c := bearerCaller("courier")
	c.IssueFP = "issue-1"
	if e.s.Match(c, "infra/a", ActionReadValue).Grant == nil {
		t.Fatal("own issue does not match")
	}
	c.IssueFP = "issue-2"
	if e.s.Match(c, "infra/a", ActionReadValue).Grant != nil {
		t.Fatal("a reissue of the token uses the old grant")
	}
}

// The token is checked inside the spend's lock, so a replacement that finished
// while the spend waited is seen, and nothing is counted.
func TestSpendChecksTokenUnderItsLock(t *testing.T) {
	e := newEnv(t)
	g := e.limited("courier", 1, "infra/a")
	c := bearerCaller("courier")
	asked := false
	c.Current = func() bool {
		asked = true
		if e.s.mu.TryLock() {
			e.s.mu.Unlock()
			t.Error("asked outside the lock")
		}
		return false
	}
	if err := e.s.Spend(c, ActionReadValue, []SpendItem{{g.ID, "infra/a"}}, false)[0]; err == nil || !asked {
		t.Fatalf("a replaced token spent a use (asked %v)", asked)
	}
	if got, _ := e.s.GetGrant(g.ID); got.UseCount != 0 {
		t.Fatal("use counted")
	}
}

// A disk that fails twice in a row can lose a use, never give one back.
func TestSpendDoubleFaultNeverGivesAUseBack(t *testing.T) {
	e := newEnv(t)
	e.limited("courier", 1, "infra/a")
	e.fs.fail("dirsync")
	if err := e.use("courier", "infra/a"); CodeOf(err) != CodeStoreWriteFailed {
		t.Fatal(err)
	}
	if e.s.Match(bearerCaller("courier"), "infra/a", ActionReadValue).Grant != nil {
		t.Fatal("still usable while the store cannot be saved")
	}
	e.fs.fail("")
	e.reopen()
	ok := 0
	for range 3 {
		if e.use("courier", "infra/a") == nil {
			ok++
		}
	}
	if ok > 1 {
		t.Fatalf("%d uses of one", ok)
	}
}

// A request that waited until the token it came with was replaced is refused
// under the lock, so it cannot expire what the new token asked for meanwhile.
func TestLateRequestFromOldTokenExpiresNothing(t *testing.T) {
	e := newEnv(t)
	in := bearerIn("courier", "infra/a")
	in.CredentialFP = "fp-new"
	fresh, _, err := e.s.Create(in)
	if err != nil {
		t.Fatal(err)
	}
	late := bearerIn("courier", "infra/b")
	late.Current = func() bool { return false }
	if _, created, err := e.s.Create(late); CodeOf(err) != CodeCredentialChanged || created {
		t.Errorf("late request: created=%v %v, want CREDENTIAL_CHANGED", created, err)
	}
	e.reopen()
	if r, _ := e.s.GetRequest(fresh.ID); r.Status != StatusPending {
		t.Errorf("the new token's request is %s, want pending", r.Status)
	}
}
