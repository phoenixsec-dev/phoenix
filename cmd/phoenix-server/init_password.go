package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/phoenixsec/phoenix/internal/crypto"
)

// minDashboardPassword is the shortest dashboard password --init accepts:
// whoever has it can approve any request.
const minDashboardPassword = 12

// promptHidden asks on the terminal without echo; an empty answer is allowed.
// A variable so tests can answer.
var promptHidden = crypto.PromptPassphraseAllowEmpty

// initDashboardPassword picks the dashboard password for --init. At a
// terminal it asks, and an empty answer means "make one up". Anywhere else
// (Docker without -it, scripts) it makes one up, because nobody can answer.
// generated tells the caller to show it: that is the only time it is seen.
func initDashboardPassword() (password string, generated bool, err error) {
	if !interactive() {
		password, err = generateDashboardPassword()
		return password, true, err
	}
	return askDashboardPassword()
}

// interactive reports whether somebody is there to answer a question.
func interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// initReveal asks, for --init, whether the dashboard may show secrets. Without
// a terminal, or with any answer but yes, it may not.
func initReveal() bool {
	return interactive() && askReveal(os.Stdin)
}

// askReveal asks once and reads one line; anything but y or yes is no.
func askReveal(in io.Reader) bool {
	fmt.Fprintln(os.Stderr, "\nThe dashboard can also show and copy your secrets, so you can use a password from your phone.")
	fmt.Fprintln(os.Stderr, "With that on, whoever knows the dashboard password can read every secret that no rule blocks.")
	fmt.Fprint(os.Stderr, "Let the dashboard show secrets? You can change this later in the config file. [y/N]: ")
	line, _ := bufio.NewReader(in).ReadString('\n') // no answer is a no
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// askDashboardPassword asks for a new dashboard password twice, or makes one
// up if the first answer is empty.
func askDashboardPassword() (password string, generated bool, err error) {
	fmt.Fprintln(os.Stderr, "Dashboard password: whoever has it can approve agents' requests. Keep it away from agents.")
	password, err = promptHidden("Choose a dashboard password (Enter to have one generated): ")
	if err != nil {
		return "", false, err
	}
	if password == "" {
		password, err = generateDashboardPassword()
		return password, true, err
	}
	if utf8.RuneCountInString(password) < minDashboardPassword {
		return "", false, fmt.Errorf("the dashboard password needs at least %d characters; nothing was created, run it again", minDashboardPassword)
	}
	confirm, err := promptHidden("Type it again: ")
	if err != nil {
		return "", false, err
	}
	if confirm != password {
		return "", false, errors.New("the passwords do not match; nothing was created, run it again")
	}
	return password, false, nil
}

// generateDashboardPassword makes a random password (100 bits) in groups of
// five letters and digits, so it can be typed on a phone.
func generateDashboardPassword() (string, error) {
	raw := make([]byte, 15)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating dashboard password: %w", err)
	}
	s := strings.ToLower(base32.StdEncoding.EncodeToString(raw))
	return s[0:5] + "-" + s[5:10] + "-" + s[10:15] + "-" + s[15:20], nil
}

// hashDashboardPassword returns the bcrypt hash that goes in the config.
// bcrypt reads at most 72 bytes, so a longer password is refused.
func hashDashboardPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if errors.Is(err, bcrypt.ErrPasswordTooLong) {
		return "", errors.New("the dashboard password is too long (72 bytes at most)")
	}
	if err != nil {
		return "", fmt.Errorf("hashing dashboard password: %w", err)
	}
	return string(hash), nil
}
