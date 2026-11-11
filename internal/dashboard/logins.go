package dashboard

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxDashboardLogins caps how many browsers can be signed in at once. A login
// past the cap signs out the one used least recently, so whoever knows the
// password is never locked out (the old single-login rule did lock people out).
const maxDashboardLogins = 5

// dashLogin is one signed-in browser. ID is public (it goes in the sign-out
// URL); nonce is the value in that browser's signed cookie and never leaves
// the server otherwise.
type dashLogin struct {
	ID        string
	nonce     string
	Device    string // short "Firefox on Android" label from the User-Agent
	UserAgent string
	IP        string // address of the most recent request
	Started   time.Time
	LastUsed  time.Time
	Expires   time.Time // same as the cookie expiry: session_ttl from sign-in
}

// loginTable holds the signed-in browsers in memory. A server restart already
// invalidates every cookie (the signing key is per process), so nothing is
// lost by not persisting it.
type loginTable struct {
	mu      sync.Mutex
	byNonce map[string]*dashLogin
}

func newLoginTable() *loginTable {
	return &loginTable{byNonce: make(map[string]*dashLogin)}
}

// add records a new login and returns the login it pushed out to stay within
// the cap, or nil.
func (lt *loginTable) add(l *dashLogin, now time.Time) *dashLogin {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.pruneLocked(now)
	var evicted *dashLogin
	if len(lt.byNonce) >= maxDashboardLogins {
		for _, old := range lt.byNonce {
			if evicted == nil || old.LastUsed.Before(evicted.LastUsed) {
				evicted = old
			}
		}
		delete(lt.byNonce, evicted.nonce)
	}
	lt.byNonce[l.nonce] = l
	return evicted
}

// valid reports whether nonce belongs to a login that is still signed in.
func (lt *loginTable) valid(nonce string, now time.Time) bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	l, ok := lt.byNonce[nonce]
	return ok && now.Before(l.Expires)
}

// touch marks a login as used now, from ip. Called once per authenticated
// request so the list shows when and where each browser was last active.
func (lt *loginTable) touch(nonce, ip string, now time.Time) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if l, ok := lt.byNonce[nonce]; ok {
		l.LastUsed = now
		if ip != "" {
			l.IP = ip
		}
	}
}

// remove signs out the login with this cookie nonce (logout).
func (lt *loginTable) remove(nonce string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.byNonce, nonce)
}

// removeByID signs out the login with this public ID (the Sessions page
// button). It returns the removed login, or nil if there was none.
func (lt *loginTable) removeByID(id string) *dashLogin {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	for nonce, l := range lt.byNonce {
		if l.ID == id {
			delete(lt.byNonce, nonce)
			return l
		}
	}
	return nil
}

// list returns copies of the signed-in logins, most recently used first.
func (lt *loginTable) list(now time.Time) []dashLogin {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.pruneLocked(now)
	out := make([]dashLogin, 0, len(lt.byNonce))
	for _, l := range lt.byNonce {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastUsed.After(out[j].LastUsed) })
	return out
}

// pruneLocked drops expired logins. Caller holds lt.mu.
func (lt *loginTable) pruneLocked(now time.Time) {
	for nonce, l := range lt.byNonce {
		if !now.Before(l.Expires) {
			delete(lt.byNonce, nonce)
		}
	}
}

// randomHex returns n random bytes as hex, for login IDs, nonces and CSRF tokens.
func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// describeDevice turns a User-Agent into a short label such as
// "Firefox on Android", good enough to tell a phone from a desktop.
func describeDevice(ua string) string {
	pick := func(pairs [][2]string) string {
		for _, p := range pairs {
			if strings.Contains(ua, p[0]) {
				return p[1]
			}
		}
		return ""
	}
	// Order matters: Edge and Opera also say "Chrome", Chrome also says
	// "Safari", Android also says "Linux", iOS also says "Mac OS X".
	browser := pick([][2]string{{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"FxiOS", "Firefox"}, {"Firefox/", "Firefox"},
		{"CriOS", "Chrome"}, {"Chrome/", "Chrome"}, {"Safari/", "Safari"}, {"curl/", "curl"}})
	system := pick([][2]string{{"Android", "Android"}, {"iPhone", "iPhone"}, {"iPad", "iPad"}, {"Windows", "Windows"},
		{"Mac OS X", "macOS"}, {"CrOS", "ChromeOS"}, {"Linux", "Linux"}})
	switch {
	case browser != "" && system != "":
		return browser + " on " + system
	case browser != "":
		return browser
	case system != "":
		return system
	}
	return "Unknown browser"
}
