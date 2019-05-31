package main // import "github.com/daaku/2f"

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"time"

	"github.com/natefinch/atomic"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/xerrors"
)

func scryptKey(password string, salt [24]byte) ([32]byte, error) {
	keyS, err := scrypt.Key([]byte(password), salt[:], 32768, 8, 1, 32)
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

func main() {
	a := app{
		file:     "/Users/naitik/2f",
		password: "hello",
		keys: []key{
			{Name: "fb"},
			{Name: "goog"},
		},
	}
	if err := a.write(); err != nil {
		log.Fatal("write", err)
	}
	if err := a.read(); err != nil {
		log.Fatal("read", err)
	}
	log.Printf("%+v\n", a)
}
