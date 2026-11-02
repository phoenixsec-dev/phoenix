package grant

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

// Parallel create / approve / revoke / delete-agent / match / tick. Run with
// -race. Afterwards the caps still hold and a restart sees exactly what
// memory had (every acknowledged transition was saved before it was published).
func TestConcurrentTransitions(t *testing.T) {
	e := newEnv(t)
	agents := []string{"a0", "a1", "a2", "a3"}
	var wg sync.WaitGroup

	for _, agent := range agents {
		for w := 0; w < 3; w++ {
			wg.Add(1)
			go func(agent string, w int) {
				defer wg.Done()
				for i := 0; i < 15; i++ {
					path := fmt.Sprintf("ns/%s-%d-%d", agent, w, i%4)
					r, _, err := e.s.Create(bearerIn(agent, path))
					if err != nil {
						continue // limits, cooldown, deleted agent: all fine here
					}
					switch i % 3 {
					case 0:
						if _, g, err := e.s.Approve(approveIn(r.ID)); err == nil {
							// Paths repeat every 4 iterations, so an older grant of the
							// same agent may match too; it must be the caller's, for
							// this path, and active.
							if m := e.s.Match(bearerCaller(agent), path, ActionReadValue); m.Grant != nil &&
								(m.Grant.Agent != agent || !slices.Contains(m.Grant.Paths, path) || !m.Grant.RevokedAt.IsZero()) {
								t.Errorf("Match returned wrong grant %+v", m.Grant)
							}
							e.s.RecordUse(g.ID)
							// After an acknowledged revoke, Match never returns that grant.
							if _, err := e.s.Revoke(RevokeInput{GrantID: g.ID, By: agent, OwnerOnly: true}); err == nil {
								if m := e.s.Match(bearerCaller(agent), path, ActionReadValue); m.Grant != nil && m.Grant.ID == g.ID {
									t.Errorf("grant %s matched after acknowledged revoke", g.ID)
								}
							}
						}
					case 1:
						e.s.Deny(DenyInput{RequestID: r.ID, Denier: "dashboard@x"})
					default:
						e.s.Approve(approveIn(r.ID))
					}
				}
			}(agent, w)
		}
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			e.s.DeleteAgent(agents[i%len(agents)], "admin", "", nil)
			e.clock.Advance(time.Second)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			e.s.Tick()
			e.s.ListGrants("", true)
			e.s.Health()
		}
	}()
	wg.Wait()
	e.s.Tick()

	now := e.clock.Now()
	pending, active := map[string]int{}, map[string]int{}
	for _, r := range e.s.ListRequests("", StatusPending) {
		pending[r.Agent]++
	}
	for _, g := range e.s.ListGrants("", false) {
		active[g.Agent]++
		if g.State(now) != GrantActive {
			t.Fatalf("inactive grant listed as active: %+v", g)
		}
	}
	for _, a := range agents {
		if pending[a] > MaxPendingPerAgent || active[a] > MaxActiveGrants {
			t.Fatalf("%s: pending %d active %d over the caps", a, pending[a], active[a])
		}
	}

	memReq, memGrants := e.s.ListRequests("", ""), e.s.ListGrants("", true)
	e.reopen()
	if got := e.s.ListRequests("", ""); len(got) != len(memReq) {
		t.Fatalf("requests after reload %d, in memory %d", len(got), len(memReq))
	}
	reloaded := e.s.ListGrants("", true)
	if len(reloaded) != len(memGrants) {
		t.Fatalf("grants after reload %d, in memory %d", len(reloaded), len(memGrants))
	}
	for i := range reloaded {
		if reloaded[i].ID != memGrants[i].ID || reloaded[i].RevokedAt.IsZero() != memGrants[i].RevokedAt.IsZero() {
			t.Fatalf("grant %s differs after reload", memGrants[i].ID)
		}
	}
}
