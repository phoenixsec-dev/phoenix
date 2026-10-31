package grant

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	bidiRLO   = string(rune(0x202E))
	zeroWidth = string(rune(0x200B))
)

func TestNormalizePaths(t *testing.T) {
	got, err := NormalizePaths([]string{"infra/b", "infra/a", "infra/b"})
	if err != nil || !slices.Equal(got, []string{"infra/a", "infra/b"}) {
		t.Fatalf("got %v %v, want de-duplicated and sorted", got, err)
	}

	eleven := make([]string, 11)
	for i := range eleven {
		eleven[i] = "ns/p" + string(rune('a'+i))
	}
	bad := map[string][]string{
		"empty":       nil,
		"too many":    eleven,
		"no slash":    {"infra"},
		"dotdot":      {"infra/../x"},
		"double /":    {"infra//x"},
		"glob star":   {"infra/*"},
		"glob ?":      {"infra/ke?"},
		"glob class":  {"infra/[ab]"},
		"glob brace":  {"infra/{a,b}"},
		"control":     {"infra/a\x07"},
		"bidi":        {"infra/a" + bidiRLO + "b"},
		"zero width":  {"infra/a" + zeroWidth},
		"bad utf8":    {"infra/\xff"},
		"overlong":    {"infra/" + strings.Repeat("x", MaxPathLen)},
		"one bad one": {"infra/ok", "infra/*"},
	}
	for name, in := range bad {
		if _, err := NormalizePaths(in); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%s: err = %v, want INVALID_REQUEST", name, err)
		}
	}
	// Ten distinct paths is the maximum and is allowed; duplicates don't count.
	if _, err := NormalizePaths(append(eleven[:10:10], eleven[0])); err != nil {
		t.Fatalf("10 distinct paths + duplicate: %v", err)
	}
}

func TestCleanText(t *testing.T) {
	got, err := CleanText("  need\tkey"+bidiRLO+zeroWidth+"\x00 now\n", MaxReasonLen)
	if err != nil || got != "need key now" {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := CleanText(strings.Repeat("é", MaxReasonLen), MaxReasonLen); err != nil {
		t.Fatalf("300 characters (multi-byte) must be allowed: %v", err)
	}
	if _, err := CleanText(strings.Repeat("x", MaxReasonLen+1), MaxReasonLen); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("301 characters: err = %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	e := newEnv(t)
	cases := map[string]struct {
		mod  func(*CreateInput)
		code Code
	}{
		"session":       {func(in *CreateInput) { in.AuthMethod = "session" }, CodeInvalidRequest},
		"bearer no fp":  {func(in *CreateInput) { in.CredentialFP = "" }, CodeInvalidRequest},
		"write action":  {func(in *CreateInput) { in.Action = "write" }, CodeActionNotGrantable},
		"blank reason":  {func(in *CreateInput) { in.Reason = " " + zeroWidth + " " }, CodeInvalidRequest},
		"negative ttl":  {func(in *CreateInput) { in.TTL = -time.Minute }, CodeInvalidRequest},
		"no agent":      {func(in *CreateInput) { in.Agent = "" }, CodeInvalidRequest},
		"glob path":     {func(in *CreateInput) { in.Paths = []string{"infra/**"} }, CodeInvalidRequest},
		"deleted agent": {func(in *CreateInput) { in.Agent = "ghost" }, CodeUnknownAgent},
	}
	e.setGone("ghost", true)
	for name, tc := range cases {
		in := bearerIn("vector", "infra/key")
		tc.mod(&in)
		_, _, err := e.s.Create(in)
		if CodeOf(err) != tc.code {
			t.Errorf("%s: err = %v, want %s", name, err, tc.code)
		}
	}

	// TTL: default, clamp up to 1m, clamp down to max.
	for _, tc := range []struct{ in, want time.Duration }{
		{0, time.Hour}, {30 * time.Second, time.Minute}, {20 * time.Hour, 8 * time.Hour},
	} {
		in := bearerIn("ttl-"+tc.in.String(), "infra/key")
		in.TTL = tc.in
		r, _, err := e.s.Create(in)
		if err != nil || r.RequestedTTL != tc.want {
			t.Errorf("ttl %v: got %v %v, want %v", tc.in, r.RequestedTTL, err, tc.want)
		}
	}
	// Short-lived token requests never carry a fingerprint.
	in := bearerIn("tok", "infra/key")
	in.AuthMethod = AuthToken
	r, _, err := e.s.Create(in)
	if err != nil || r.CredentialFP != "" {
		t.Fatalf("token request: fp=%q err=%v", r.CredentialFP, err)
	}
}

// Review P3-R2: every Unicode format character (Cf) is rejected, not just
// the listed bidi and zero-width ones. A soft hyphen is invisible in the
// approval prompt, so "pro<U+00AD>duction" would look like "production".
func TestNormalizePathsRejectsAllFormatChars(t *testing.T) {
	for _, p := range []string{"infra/pro­duction", "infra/a⁡b", "infra/\U000e0001tag"} {
		if _, err := NormalizePaths([]string{p}); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
	if _, err := NormalizePaths([]string{"infra/café/key"}); err != nil {
		t.Errorf("ordinary Unicode path rejected: %v", err)
	}
}
