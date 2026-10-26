package crypto

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/phoenixsec/phoenix/internal/fsutil"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	// Argon2id parameters — OWASP recommended minimums.
	defaultKDFTime    = 3
	defaultKDFMemory  = 65536 // 64 MB
	defaultKDFThreads = 4
	saltSize          = 16
)

// ProtectedKeyFile is the on-disk JSON format for a passphrase-protected master key.
type ProtectedKeyFile struct {
	Version    int    `json:"phoenix_protected_key"`
	KDF        string `json:"kdf"`
	KDFTime    uint32 `json:"kdf_time"`
	KDFMemory  uint32 `json:"kdf_memory"`
	KDFThreads uint8  `json:"kdf_threads"`
	Salt       string `json:"salt"`       // base64
	Nonce      string `json:"nonce"`      // base64
	Ciphertext string `json:"ciphertext"` // base64 (encrypted key + GCM tag)
}

// IsProtectedKeyFile returns true if the data looks like a JSON-encoded
// protected key file rather than raw base64.
func IsProtectedKeyFile(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// DeriveKeyFromPassphrase derives a 32-byte key from a passphrase using Argon2id.
func DeriveKeyFromPassphrase(passphrase string, salt []byte, time, memory uint32, threads uint8) []byte {
	return argon2.IDKey([]byte(passphrase), salt, time, memory, threads, KeySize)
}

// EncryptMasterKey encrypts a master key with a passphrase.
func EncryptMasterKey(masterKey []byte, passphrase string) (*ProtectedKeyFile, error) {
	if len(masterKey) != KeySize {
		return nil, ErrInvalidKey
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	derived := DeriveKeyFromPassphrase(passphrase, salt, defaultKDFTime, defaultKDFMemory, defaultKDFThreads)
	defer ZeroBytes(derived)

	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, masterKey, nil)

	return &ProtectedKeyFile{
		Version:    1,
		KDF:        "argon2id",
		KDFTime:    defaultKDFTime,
		KDFMemory:  defaultKDFMemory,
		KDFThreads: defaultKDFThreads,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// maxKDFMemory is the upper bound for KDF memory parameter (4 GB).
// Prevents a malformed key file from causing an OOM.
const maxKDFMemory = 4 * 1024 * 1024 // in KiB = 4 GB

// validateKDFParams checks that KDF parameters are safe to use.
func validateKDFParams(pf *ProtectedKeyFile) error {
	if pf.KDF != "argon2id" {
		return fmt.Errorf("unsupported KDF: %q", pf.KDF)
	}
	if pf.KDFThreads == 0 {
		return fmt.Errorf("invalid kdf_threads: must be >= 1")
	}
	if pf.KDFTime == 0 {
		return fmt.Errorf("invalid kdf_time: must be >= 1")
	}
	if pf.KDFMemory == 0 {
		return fmt.Errorf("invalid kdf_memory: must be >= 1")
	}
	if pf.KDFMemory > maxKDFMemory {
		return fmt.Errorf("kdf_memory %d KiB exceeds maximum %d KiB", pf.KDFMemory, maxKDFMemory)
	}
	return nil
}

// DecryptMasterKey decrypts a protected key file with a passphrase.
func DecryptMasterKey(pf *ProtectedKeyFile, passphrase string) ([]byte, error) {
	if err := validateKDFParams(pf); err != nil {
		return nil, fmt.Errorf("invalid protected key file: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(pf.Salt)
	if err != nil {
		return nil, fmt.Errorf("decoding salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(pf.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decoding nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(pf.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}

	derived := DeriveKeyFromPassphrase(passphrase, salt, pf.KDFTime, pf.KDFMemory, pf.KDFThreads)
	defer ZeroBytes(derived)

	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	key, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("wrong passphrase or corrupted key file")
	}

	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	return key, nil
}

// SaveProtectedMasterKey encrypts the master key with a passphrase and writes
// it to disk crash-safely (fsynced write-tmp + rename).
func SaveProtectedMasterKey(path string, masterKey []byte, passphrase string) error {
	pf, err := EncryptMasterKey(masterKey, passphrase)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling protected key: %w", err)
	}

	if err := fsutil.WriteFileAtomic(path, data, 0600); err != nil {
		return fmt.Errorf("saving protected key file: %w", err)
	}
	return nil
}

// IsTerminal returns true if stdin is a TTY.
func IsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// PromptPassphrase prompts for a passphrase on the TTY with hidden input.
// Returns an error if the input is empty or the terminal is unavailable.
func PromptPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading from terminal: %w", err)
	}
	pp := string(pw)
	if pp == "" {
		return "", fmt.Errorf("empty passphrase")
	}
	return pp, nil
}

// PromptPassphraseAllowEmpty prompts for a passphrase on the TTY with hidden input.
// Unlike PromptPassphrase, an empty input is returned as "" without error.
func PromptPassphraseAllowEmpty(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading from terminal: %w", err)
	}
	return string(pw), nil
}

// PromptHiddenMultiline prompts on the TTY and reads possibly multi-line input
// (PEM keys, certs) with echo off until the user presses Ctrl-D. The terminal
// is put in raw mode so nothing is echoed and Ctrl-C can be caught and the
// terminal restored, instead of the process dying with echo still off.
func PromptHiddenMultiline(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	fmt.Fprint(os.Stderr, prompt)
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Fprintln(os.Stderr)
		return "", fmt.Errorf("reading from terminal: %w", err)
	}
	value, readErr := collectHiddenInput(os.Stdin)
	term.Restore(fd, oldState)
	fmt.Fprintln(os.Stderr)
	return value, readErr
}

// collectHiddenInput turns raw-mode keystrokes into text. Raw mode delivers
// keys untranslated, so this does the terminal's usual job: Ctrl-D ends input,
// Ctrl-C aborts, Enter (CR) becomes a newline, and backspace drops the last
// byte. Bracketed-paste markers are stripped in case the terminal sends them.
func collectHiddenInput(r io.Reader) (string, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		for _, b := range buf[:n] {
			switch b {
			case 0x04: // Ctrl-D
				return finishHiddenInput(out), nil
			case 0x03: // Ctrl-C
				return "", fmt.Errorf("cancelled")
			case 0x7f, 0x08: // backspace
				if len(out) > 0 {
					out = out[:len(out)-1]
				}
			default:
				out = append(out, b)
			}
		}
		if err == io.EOF {
			return finishHiddenInput(out), nil
		}
		if err != nil {
			return "", fmt.Errorf("reading from terminal: %w", err)
		}
	}
}

func finishHiddenInput(b []byte) string {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\x1b[200~", "")
	s = strings.ReplaceAll(s, "\x1b[201~", "")
	return s
}

// ReadPassphrase reads a passphrase using the priority chain:
//  1. If stdinPipe is true, read one line from stdin
//  2. PHOENIX_MASTER_PASSPHRASE env var
//  3. Interactive TTY prompt
//  4. Error listing the three options
func ReadPassphrase(stdinPipe bool) (string, error) {
	// 1. stdin pipe
	if stdinPipe {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			pp := strings.TrimRight(scanner.Text(), "\r\n")
			if pp == "" {
				return "", fmt.Errorf("empty passphrase read from stdin")
			}
			return pp, nil
		}
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("reading passphrase from stdin: %w", err)
		}
		return "", fmt.Errorf("no passphrase provided on stdin")
	}

	// 2. env var
	if pp := os.Getenv("PHOENIX_MASTER_PASSPHRASE"); pp != "" {
		return pp, nil
	}

	// 3. interactive TTY
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Enter master key passphrase: ")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr) // newline after hidden input
		if err != nil {
			return "", fmt.Errorf("reading passphrase from terminal: %w", err)
		}
		pp := string(pw)
		if pp == "" {
			return "", fmt.Errorf("empty passphrase")
		}
		return pp, nil
	}

	// 4. no method available
	return "", fmt.Errorf("master key is passphrase-protected; provide passphrase via:\n" +
		"  --passphrase-stdin     pipe passphrase on stdin\n" +
		"  PHOENIX_MASTER_PASSPHRASE  environment variable\n" +
		"  interactive terminal   run with a TTY attached")
}
