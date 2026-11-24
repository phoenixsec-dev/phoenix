package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/phoenixsec/phoenix/internal/acl"
	"github.com/phoenixsec/phoenix/internal/api"
	"github.com/phoenixsec/phoenix/internal/audit"
	"github.com/phoenixsec/phoenix/internal/crypto"
	"github.com/phoenixsec/phoenix/internal/policy"
	"github.com/phoenixsec/phoenix/internal/store"
)

// oddNames are legal secret names that, unescaped in a URL, are another name.
// The last one is the percent-encoding of app/key itself.
var oddNames = []string{"app/key?v2", "app/key#old", "app/key%20x", "app/100%", "app/./key", "app/a&b=c+d;e", "app/%6bey"}

// namesEnv is a real server with one plain secret, app/key, to damage.
type namesEnv struct {
	st  *store.Store
	acl *acl.ACL
}

// withNamesServer runs fn with the CLI pointed at a real server.
func withNamesServer(t *testing.T, fn func(namesEnv)) {
	t.Helper()
	t.Setenv("PHOENIX_ROLE", "")
	t.Setenv("PHOENIX_SEAL_KEY", "")
	mk, err := crypto.GenerateAndSaveMasterKey(filepath.Join(t.TempDir(), "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.New(filepath.Join(t.TempDir(), "store.json"), mk)
	if err != nil {
		t.Fatal(err)
	}
	a := acl.NewFromConfig(&acl.ACLConfig{Agents: map[string]acl.Agent{}})
	if err := a.AddAgent("admin", "test-token", []acl.Permission{{Path: "*", Actions: []acl.Action{acl.ActionAdmin}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.Set("app/key", "plain", "test", "the plain one", nil); err != nil {
		t.Fatal(err)
	}
	srv := api.NewServer(store.NewFileBackend(st), a, audit.NewWriterLogger(io.Discard), "")
	withMockServer(t, srv.ServeHTTP, func() { fn(namesEnv{st, a}) })
}

// value is what the store holds under a name, "" if nothing.
func (e namesEnv) value(name string) string {
	s, err := e.st.Get(name)
	if err != nil {
		return ""
	}
	return s.Value
}

// run runs one command with stdin and returns what it printed.
func run(t *testing.T, stdin string, cmd func() error) (string, error) {
	t.Helper()
	return runOpenClawExecProviderCommandWithStdinResult(t, stdin, cmd)
}

// Every command that takes a secret's name acts on that name and no other, and
// names with ?, # or % that already exist can be read, listed, changed and
// deleted.
func TestCommandsActOnTheNameTyped(t *testing.T) {
	for _, name := range oddNames {
		t.Run(name, func(t *testing.T) {
			withNamesServer(t, func(e namesEnv) {
				must := func(what string, err error) {
					t.Helper()
					if err != nil {
						t.Errorf("%s: %v", what, err)
					}
				}
				// reset puts both secrets back, so each command is judged alone.
				reset := func() {
					t.Helper()
					must("reset", e.st.Set(name, "odd", "test", "the odd one", nil))
					must("reset", e.st.Set("app/key", "plain", "test", "the plain one", nil))
				}
				_, err := run(t, "odd", func() error { return cmdSet([]string{name, "--value-stdin", "-d", "the odd one"}) })
				must("set", err)
				if e.value(name) != "odd" || e.value("app/key") != "plain" {
					t.Error("set wrote the wrong secret")
				}
				reset()
				if out, err := run(t, "", func() error { return cmdGet([]string{name}) }); err != nil || out != "odd" {
					t.Errorf("get read the wrong secret (%v)", err)
				}
				if out, bad := mcpToolGet(json.RawMessage(fmt.Sprintf(`{"path":%q}`, name)), quietLog()); bad || out != "odd" {
					t.Errorf("phoenix_get read the wrong secret (failed: %v)", bad)
				}
				if out, err := run(t, "", func() error { return cmdInfo([]string{name}) }); err != nil || !strings.Contains(out, "the odd one") {
					t.Errorf("info: %q, %v", out, err)
				}
				out, err := run(t, "", func() error { return cmdExport([]string{"app/"}) })
				must("export", err)
				if strings.Count(out, "=plain\n") != 1 || strings.Count(out, "=odd\n") != 1 {
					t.Errorf("export read the wrong secret: %d lines", strings.Count(out, "\n"))
				}
				if out, err := run(t, "", func() error { return cmdResolve([]string{"phoenix://" + name}) }); err != nil || strings.TrimSpace(out) != "odd" {
					t.Errorf("resolve read the wrong secret (%v)", err)
				}
				_, err = run(t, "", func() error { return cmdDescribe([]string{name, "-d", "changed"}) })
				must("describe", err)
				for path, want := range map[string]string{name: "changed", "app/key": "the plain one"} {
					if s, err := e.st.Get(path); err != nil || s.Metadata.Description != want {
						t.Errorf("describe changed the wrong secret (%s, %v)", path, err)
					}
				}
				reset()
				_, err = run(t, "", func() error { return cmdDelete([]string{name}) })
				must("delete", err)
				if e.value(name) != "" || e.value("app/key") != "plain" {
					t.Error("delete removed the wrong secret")
				}
			})
		})
	}
}

// Folders too: list, export and phoenix_list name the folder that was typed.
func TestFoldersWithOddNames(t *testing.T) {
	for _, folder := range []string{"a#b", "a%62", "50%"} {
		withNamesServer(t, func(e namesEnv) {
			for _, p := range []string{folder + "/in", "ab/other", "a/other"} {
				if err := e.st.Set(p, "v", "test", "", nil); err != nil {
					t.Fatal(err)
				}
			}
			want := folder + "/in"
			for _, args := range [][]string{{folder, "--names"}, {folder}} {
				if out, err := run(t, "", func() error { return cmdList(args) }); err != nil || strings.Fields(out)[0] != want || strings.Contains(out, "other") {
					t.Errorf("list %v = %q, %v", args, out, err)
				}
			}
			arg := json.RawMessage(fmt.Sprintf(`{"prefix":%q}`, folder))
			if out, bad := mcpToolList(arg, quietLog()); bad || !strings.HasPrefix(out, want) || strings.Contains(out, "other") {
				t.Errorf("phoenix_list = %q", out)
			}
			// The route used against servers without /v1/metadata.
			if out, bad := mcpToolListPaths(folder+"/", quietLog()); bad || out != want {
				t.Errorf("phoenix_list, old route = %q", out)
			}
			if out, err := run(t, "", func() error { return cmdExport([]string{folder + "/"}) }); err != nil || out != "IN=v\n" {
				t.Errorf("export = %q, %v", out, err)
			}
		})
	}
}

// Imports write under the prefix that was typed, and --skip-existing looks at
// that name too.
func TestImportsWithOddPrefix(t *testing.T) {
	withNamesServer(t, func(e namesEnv) {
		env := filepath.Join(t.TempDir(), "env")
		if err := os.WriteFile(env, []byte("DB_PASS=imported\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := run(t, "", func() error { return cmdImport([]string{env, "-p", "app/key#2/"}) }); err != nil {
			t.Fatal(err)
		}
		if e.value("app/key#2/db-pass") != "imported" || e.value("app/key") != "plain" {
			t.Error("env import wrote the wrong secret")
		}

		fake := writeFakeOP(t, `echo '{"id":"i1","title":"Shop","category":"LOGIN","fields":[{"id":"f1","type":"CONCEALED","label":"password","value":"from-op"}]}'`)
		t.Setenv("PATH", filepath.Dir(fake)+":"+os.Getenv("PATH"))
		t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "fake")
		// With the # cut off, --skip-existing would find app/key and skip it.
		for _, skipExisting := range []bool{true, false} {
			if _, err := run(t, "", func() error { return import1Password("vault", "Shop", "app/key#", false, skipExisting) }); err != nil {
				t.Fatal(err)
			}
			if e.value("app/key#shop/password") != "from-op" || e.value("app/key") != "plain" {
				t.Error("1Password import wrote the wrong secret")
			}
		}
	})
}

// "phoenix agent delete 'x?y'" used to delete the agent x.
func TestAgentCommandsActOnTheNameTyped(t *testing.T) {
	withNamesServer(t, func(e namesEnv) {
		for _, n := range []string{"bob", "bob?x"} {
			if err := e.acl.AddAgent(n, "token of "+n, []acl.Permission{{Path: "app/*", Actions: []acl.Action{acl.ActionList}}}); err != nil {
				t.Fatal(err)
			}
		}
		if out, err := run(t, "", func() error { return cmdKeypairShow([]string{"bob?x"}) }); err != nil || !strings.Contains(out, "Agent: bob?x\n") {
			t.Errorf("keypair show = %q, %v", out, err)
		}
		if _, err := run(t, "", func() error { return cmdAgentDelete([]string{"bob?x"}) }); err != nil {
			t.Error(err)
		}
		if names := e.acl.ListAgents(); !slices.Contains(names, "bob") || slices.Contains(names, "bob?x") {
			t.Errorf("agents left: %v", names)
		}
		if _, err := run(t, "", func() error { return cmdAgentDelete([]string{"bob#x"}) }); err == nil || !slices.Contains(e.acl.ListAgents(), "bob") {
			t.Errorf("deleting an agent that does not exist: %v", err)
		}
	})
}

// A name the server never accepts is refused. It used to be redirected to
// app/key: set and delete said ok and did nothing, get printed another value.
func TestRedirectedNamesAreRefused(t *testing.T) {
	withNamesServer(t, func(e namesEnv) {
		for _, name := range []string{"/app/key", "app//key", "x/../app/key"} {
			if _, err := run(t, "new", func() error { return cmdSet([]string{name, "--value-stdin"}) }); err == nil {
				t.Errorf("set %s said ok", name)
			}
			if _, err := run(t, "", func() error { return cmdDelete([]string{name}) }); err == nil {
				t.Errorf("delete %s said ok", name)
			}
			if _, err := run(t, "", func() error { return cmdGet([]string{name}) }); err == nil {
				t.Errorf("get %s printed a value", name)
			}
		}
		if e.value("app/key") != "plain" {
			t.Error("app/key was changed")
		}
	})
}

// The unseal check asks about the sealed value's own name, and an answer about
// another name is not a yes.
func TestUnsealCheckIsAboutTheNameAsked(t *testing.T) {
	kp, err := crypto.GenerateSealKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	withSealKey(t, &kp.PrivateKey)
	unseal := func(name string) (string, bool) {
		env, err := crypto.SealValue(name, "", "sealed-fake", &kp.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(env)
		arg, _ := json.Marshal(map[string]string{"sealed": "PHOENIX_SEALED:" + base64.StdEncoding.EncodeToString(b)})
		return mcpToolUnseal(arg, quietLog())
	}
	pe, err := policy.Load([]byte(`{"attestation":{"open/key":{"allow_unseal":true},"shut/*":{},"open/key#x":{},"open/a&b":{"allow_unseal":true}}}`))
	if err != nil {
		t.Fatal(err)
	}
	a := acl.NewFromConfig(&acl.ACLConfig{Agents: map[string]acl.Agent{}})
	if err := a.AddAgent("admin", "test-token", []acl.Permission{{Path: "*", Actions: []acl.Action{acl.ActionAdmin}}}); err != nil {
		t.Fatal(err)
	}
	srv := api.NewServer(nil, a, audit.NewWriterLogger(io.Discard), "")
	srv.SetPolicy(pe)
	withMockServer(t, srv.ServeHTTP, func() {
		for _, name := range []string{"open/key#x", "open/key&y", "open/%6bey", "shut/a+b"} {
			if _, bad := unseal(name); !bad {
				t.Errorf("%s was unsealed with another name's rule", name)
			}
		}
		for _, name := range []string{"open/key", "open/a&b"} {
			if out, bad := unseal(name); bad {
				t.Errorf("%s was not unsealed: %s", name, out)
			}
		}
	})
	withMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"path":"open/key","check":"allow_unseal","allowed":true}`))
	}, func() {
		if _, bad := unseal("shut/key"); !bad {
			t.Error("a yes about open/key unsealed shut/key")
		}
	})
}

// quietLog is a logger for MCP tools that writes nowhere.
func quietLog() *log.Logger { return log.New(io.Discard, "", 0) }
