package main // import "github.com/daaku/2f"

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/natefinch/atomic"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/xerrors"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func scryptKey(password []byte, salt [24]byte) ([32]byte, error) {
	keyS, err := scrypt.Key(password, salt[:], 1<<20, 8, 1, 32)
	var key [32]byte
	copy(key[:], keyS[:32])
	return key, err
}

func prompt(p string) (string, error) {
	fmt.Printf(p)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", xerrors.Errorf("2f: error reading %s: %w", p, err)
	}
	return text[:len(text)-1], nil
}

func promptPassword(p string) ([]byte, error) {
	fmt.Printf(p)
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, xerrors.Errorf("2f: error reading %s: %w", p, err)
	}
	fmt.Println()
	return password, nil
}

type key struct {
	Name   string
	Digits int
	Key    []byte
}

func (k *key) generate(t time.Time) string {
	counter := uint64(t.UnixNano()) / 30e9
	h := hmac.New(sha1.New, k.Key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < k.Digits && i < 8; i++ {
		d *= 10
	}
	return fmt.Sprintf("%0*d", k.Digits, int(v%d))
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

	sort.Slice(a.keys, func(i, j int) bool {
		return a.keys[i].Name < a.keys[j].Name
	})
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

func (a *app) raw() error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	for _, k := range a.keys {
		fmt.Fprintf(w, "%s\t| %d\t| %s\t\n", k.Name, k.Digits,
			b32.EncodeToString(k.Key))
	}
	return w.Flush()
}

func (a *app) list() error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	now := time.Now()
	for _, k := range a.keys {
		fmt.Fprintf(w, "%s\t  %s\t\n", k.Name, k.generate(now))
	}
	return w.Flush()
}

func (a *app) add() error {
	for {
		name, err := prompt("name: ")
		if err != nil {
			return err
		}
		if name == "" {
			break
		}

		digitsString, err := prompt("digits (default 6): ")
		if err != nil {
			return err
		}
		digits := 6
		if digitsString != "" {
			digits, _ = strconv.Atoi(digitsString)
			if digits != 6 || digits != 7 || digits != 8 {
				return xerrors.New("2f: digits must be one of 6, 7 or 8")
			}
		}

		keyB64, err := prompt("key: ")
		if err != nil {
			return err
		}
		keyBytes, err := b32.DecodeString(strings.ToUpper(keyB64))
		if err != nil {
			return xerrors.Errorf("2f: invalid key %q: %w", keyB64, err)
		}

		a.keys = append(a.keys, key{
			Name:   name,
			Digits: digits,
			Key:    keyBytes,
		})
	}

	return a.write()
}

func (a *app) rm() error {
	name, err := prompt("exact name to remove: ")
	if err != nil {
		return err
	}

	keys := make([]key, 0, len(a.keys))
	for _, k := range a.keys {
		if k.Name != name {
			keys = append(keys, k)
		}
	}
	a.keys = keys
	return a.write()
}

func (a *app) changePassword() error {
	var err error
	a.password, err = promptPassword("new password: ")
	if err != nil {
		return err
	}
	return a.write()
}

func (a *app) run(cmd string) error {
	var err error
	a.password, err = promptPassword("password: ")
	if err != nil {
		return err
	}

	if err := a.read(); err != nil {
		return err
	}
	switch cmd {
	case "list":
		return a.list()
	case "raw":
		return a.raw()
	case "add":
		return a.add()
	case "rm":
		return a.rm()
	case "passwd":
		return a.changePassword()
	}
	return xerrors.Errorf("2f: unknown command %q", cmd)
}

func main() {
	a := app{file: fmt.Sprintf("%s/.2f", os.Getenv("HOME"))}
	flag.StringVar(&a.file, "f", a.file, "file to store data")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "2f: unexpected arguments")
		fmt.Fprintln(os.Stderr, "usage: 2f [-f file] list|add|rm|passwd|raw")
		flag.PrintDefaults()
	}
	flag.Parse()
	if len(flag.Args()) > 1 {
		flag.Usage()
		os.Exit(1)
	}
	cmd := "list"
	if len(flag.Args()) == 1 {
		cmd = flag.Arg(0)
	}
	if err := a.run(cmd); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
