package ui

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// ReadPassphrase asks for a passphrase without echoing it.
//
// When confirm is set the passphrase is asked for twice. That is not
// ceremony: a mistyped passphrase on a backup nobody can open again is
// indistinguishable from having no backup at all, and the mistake is only
// discovered when it matters most.
func ReadPassphrase(prompt string, confirm bool) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return readPassphraseFromPipe()
	}

	fmt.Fprint(os.Stderr, prompt+": ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(first) == 0 {
		return nil, errors.New("an empty passphrase is not a passphrase")
	}
	if !confirm {
		return first, nil
	}

	fmt.Fprint(os.Stderr, "Repeat the passphrase: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(first, second) {
		for i := range second {
			second[i] = 0
		}
		return nil, errors.New("the two passphrases differ")
	}
	return first, nil
}

// readPassphraseFromPipe accepts a passphrase on standard input when there is
// no terminal, which is how a scheduled job supplies one without putting it on
// a command line.
func readPassphraseFromPipe() ([]byte, error) {
	line, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, errors.New("no terminal to ask for a passphrase, and nothing on standard input")
	}
	line = bytes.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, errors.New("an empty passphrase is not a passphrase")
	}
	return line, nil
}

// Confirm asks a yes/no question, defaulting to no.
func Confirm(question string) bool {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	switch len(line) {
	case 0:
		return false
	default:
		return line[0] == 'y' || line[0] == 'Y'
	}
}
