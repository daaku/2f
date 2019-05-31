package main // import "github.com/daaku/2f"

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"text/tabwriter"
	"time"

	"github.com/natefinch/atomic"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/xerrors"
)

func scryptKey(password []byte, salt [24]byte) ([32]byte, error) {
	keyS, err := scrypt.Key(password, salt[:], 32768, 8, 1, 32)
	var key [32]byte
	copy(key[:], keyS[:32])
	return key, err
}

type key struct {
	Name   string
	Digits int
	Key    []byte
}

func (k *key) generate(t time.Time) int {
	return 0
}

type encFile struct {
	PasswordSalt [24]byte
	Nonce        [24]byte
	Payload      []byte
}

type app struct {
	file     string
	password []byte

	keys []key
}

func (a *app) read() error {
	data, err := ioutil.ReadFile(a.file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return xerrors.Errorf("2f: error reading file %q: %w", a.file, err)
	}

	var file encFile
	if err := json.Unmarshal(data, &file); err != nil {
		return xerrors.Errorf("2f: error decoding file: %w", err)
	}

	sealKey, err := scryptKey(a.password, file.PasswordSalt)
	if err != nil {
		return xerrors.Errorf("2f: error deriving key: %w", err)
	}

	decrypted, ok := secretbox.Open(nil, file.Payload, &file.Nonce, &sealKey)
	if !ok {
		return xerrors.Errorf("2f: error decrypting data")
	}

	if err := json.Unmarshal(decrypted, &a.keys); err != nil {
		return xerrors.Errorf("2f: error unmarshaling keys: %w", err)
	}

	return nil
}

func (a *app) write() error {
	var file encFile

	if _, err := io.ReadFull(rand.Reader, file.Nonce[:]); err != nil {
		return xerrors.Errorf("2f: error populating nonce: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, file.PasswordSalt[:]); err != nil {
		return xerrors.Errorf("2f: error populating password salt: %w", err)
	}

	sealKey, err := scryptKey(a.password, file.PasswordSalt)
	if err != nil {
		return xerrors.Errorf("2f: error deriving key: %w", err)
	}

	keysJSON, err := json.Marshal(a.keys)
	if err != nil {
		return xerrors.Errorf("2f: error marshaling keys: %w", err)
	}

	file.Payload = secretbox.Seal(nil, keysJSON, &file.Nonce, &sealKey)
	fileJSON, err := json.Marshal(file)
	if err != nil {
		return xerrors.Errorf("2f: error marshaling file: %w", err)
	}

	if err := atomic.WriteFile(a.file, bytes.NewReader(fileJSON)); err != nil {
		return xerrors.Errorf("2f: writing file %q: %w", a.file, err)
	}

	return nil
}

func (a *app) list() error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, '.', tabwriter.AlignRight|tabwriter.Debug)
	for _, k := range a.keys {
		fmt.Fprintf(w, "%s\t%s\t%s\n", k.Name, k.Digits, k.Key)
	}
	return w.Flush()
}

func (a *app) run(cmd string) error {
	fmt.Printf("password: ")
	var err error
	a.password, err = terminal.ReadPassword(0)
	if err != nil {
		return xerrors.Errorf("2f: error reading password: %w", err)
	}
	fmt.Println()

	if err := a.read(); err != nil {
		return err
	}
	switch cmd {
	case "list":
		return a.list()
	}
	return xerrors.Errorf("2f: unknown command %q", cmd)
}

func main() {
	a := app{file: fmt.Sprintf("%s/.2f", os.Getenv("HOME"))}
	flag.StringVar(&a.file, "f", a.file, "file to store data")
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Fprintln(os.Stderr, "2f: unexpected arguments")
		fmt.Fprintln(os.Stderr, "usage: 2f [-f file] list|add")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if err := a.run(flag.Arg(0)); err != nil {
		fmt.Fprintf(os.Stderr, "%+v", err)
		os.Exit(1)
	}
}
