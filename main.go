package main // import "github.com/daaku/2f"

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"time"

	"github.com/natefinch/atomic"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/xerrors"
)

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
	password string

	keys []key
}

func (a *app) read() error {
	data, err := ioutil.ReadFile(a.file)
	if err != nil {
		return xerrors.Errorf("2f: error reading file %q: %w", a.file, err)
	}

	var file encFile
	if err := json.Unmarshal(data, &file); err != nil {
		return xerrors.Errorf("2f: error decoding file: %w", err)
	}

	keyS, err := scrypt.Key([]byte(a.password), file.PasswordSalt[:], 32768, 8, 1, 32)
	if err != nil {
		return xerrors.Errorf("2f: error deriving key: %w", err)
	}
	var key [32]byte
	copy(key[:], keyS[:32])

	decrypted, ok := secretbox.Open(nil, file.Payload, &file.Nonce, &key)
	if !ok {
		return xerrors.Errorf("2f: error decrypting data")
	}

	fmt.Printf("%s\n", decrypted)
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

	keyS, err := scrypt.Key([]byte(a.password), file.PasswordSalt[:], 32768, 8, 1, 32)
	if err != nil {
		return xerrors.Errorf("2f: error deriving key: %w", err)
	}
	var key [32]byte
	copy(key[:], keyS[:32])

	keysJSON, err := json.Marshal(a.keys)
	if err != nil {
		return xerrors.Errorf("2f: error marshaling keys: %w", err)
	}

	file.Payload = secretbox.Seal(nil, keysJSON, &file.Nonce, &key)
	fileJSON, err := json.Marshal(file)
	if err != nil {
		return xerrors.Errorf("2f: error marshaling file: %w", err)
	}

	if err := atomic.WriteFile(a.file, bytes.NewReader(fileJSON)); err != nil {
		return xerrors.Errorf("2f: writing file %q: %w", a.file, err)
	}

	return nil
}

func main() {
	a := app{
		file:     "/Users/naitik/2f",
		password: "hello",
	}
	if err := a.write(); err != nil {
		log.Fatal("write", err)
	}
	if err := a.read(); err != nil {
		log.Fatal("read", err)
	}
}
