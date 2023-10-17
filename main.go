package main // import "github.com/daaku/2f"

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/daaku/qrterm"
	"github.com/natefinch/atomic"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
	"rsc.io/qr"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func scryptKey(password []byte, salt [24]byte) ([32]byte, error) {
	keyS, err := scrypt.Key(password, salt[:], 1<<20, 8, 1, 32)
	var key [32]byte
	copy(key[:], keyS[:32])
	return key, err
}

func prompt(p string) (string, error) {
	fmt.Print(p)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", errors.WithStack(err)
	}
	return text[:len(text)-1], nil
}

func promptPassword(p string) ([]byte, error) {
	fmt.Print(p)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	fmt.Println()
	return password, nil
}

type key struct {
	Name   string
	Key    []byte
	Digits int
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
	Payload      []byte
	PasswordSalt [24]byte
	Nonce        [24]byte
}

type app struct {
	file     string
	password []byte

	keys []key
}

func (a *app) read() error {
	data, err := os.ReadFile(a.file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return errors.Wrapf(err, "reading file %q", a.file)
	}

	var file encFile
	if err := json.Unmarshal(data, &file); err != nil {
		return errors.Wrap(err, "decoding file")
	}

	sealKey, err := scryptKey(a.password, file.PasswordSalt)
	if err != nil {
		return errors.WithStack(err)
	}

	decrypted, ok := secretbox.Open(nil, file.Payload, &file.Nonce, &sealKey)
	if !ok {
		return errors.New("error decrypting data")
	}

	if err := json.Unmarshal(decrypted, &a.keys); err != nil {
		return errors.Wrap(err, "unmarshaling keys")
	}

	return nil
}

func (a *app) write() error {
	var file encFile

	if _, err := io.ReadFull(rand.Reader, file.Nonce[:]); err != nil {
		return errors.WithStack(err)
	}
	if _, err := io.ReadFull(rand.Reader, file.PasswordSalt[:]); err != nil {
		return errors.WithStack(err)
	}

	sealKey, err := scryptKey(a.password, file.PasswordSalt)
	if err != nil {
		return errors.WithStack(err)
	}

	sort.Slice(a.keys, func(i, j int) bool {
		return a.keys[i].Name < a.keys[j].Name
	})
	keysJSON, err := json.Marshal(a.keys)
	if err != nil {
		return errors.WithStack(err)
	}

	file.Payload = secretbox.Seal(nil, keysJSON, &file.Nonce, &sealKey)
	fileJSON, err := json.Marshal(file)
	if err != nil {
		return errors.WithStack(err)
	}

	if err := atomic.WriteFile(a.file, bytes.NewReader(fileJSON)); err != nil {
		return errors.WithMessagef(err, "writing file %q", a.file)
	}

	return nil
}

func (a *app) importF(file string) error {
	contents, err := os.ReadFile(file)
	if err != nil {
		return errors.Wrapf(err, "in opening %q", file)
	}
	r := csv.NewReader(bytes.NewReader(contents))
	records, err := r.ReadAll()
	if err != nil {
		return errors.Wrapf(err, "importing from %q", file)
	}
	for _, row := range records {
		digits, _ := strconv.Atoi(row[1])
		if digits < 6 || digits > 8 {
			return errors.New("digits must be one of 6, 7 or 8")
		}
		keyBytes, err := b32.DecodeString(strings.ToUpper(row[2]))
		if err != nil {
			return errors.Wrapf(err, "invalid key %q", row[2])
		}
		a.keys = append(a.keys, key{
			Name:   row[0],
			Digits: digits,
			Key:    keyBytes,
		})
	}
	return a.write()
}

func (a *app) export(file string) error {
	var w bytes.Buffer
	cw := csv.NewWriter(&w)
	for _, k := range a.keys {
		row := []string{
			k.Name,
			fmt.Sprint(k.Digits),
			b32.EncodeToString(k.Key),
		}
		if err := cw.Write(row); err != nil {
			return errors.WithStack(err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return errors.WithStack(err)
	}
	if err := os.WriteFile(file, w.Bytes(), 0600); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (a *app) list() error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	now := time.Now()
	for _, k := range a.keys {
		fmt.Fprintf(w, "%s\t  %s\t%s\n", k.Name, k.generate(now), k.generate(now.Add(30*time.Second)))
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
			if digits < 6 || digits > 8 {
				return errors.New("digits must be one of 6, 7 or 8")
			}
		}

		keyB64, err := prompt("key: ")
		if err != nil {
			return err
		}
		keyBytes, err := b32.DecodeString(strings.ToUpper(keyB64))
		if err != nil {
			return errors.Wrapf(err, "invalid key %q", keyB64)
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

func (a *app) qr(name string) error {
	all := name == "all"
	for _, k := range a.keys {
		if k.Name == name || all {
			key := b32.EncodeToString(k.Key)
			url := fmt.Sprintf("otpauth://totp/%s?secret=%s", k.Name, key)
			code, err := qr.Encode(url, qr.L)
			if err != nil {
				return errors.WithStack(err)
			}
			if all {
				fmt.Println(k.Name)
			}
			if err := qrterm.WriteSmall(os.Stdout, code); err != nil {
				return errors.WithStack(err)
			}
		}
	}
	return nil
}

func (a *app) version() error {
	bi, _ := debug.ReadBuildInfo()
	_, err := os.Stdout.WriteString(bi.String())
	return errors.WithStack(err)
}

func (a *app) run(cmd string, arg string) error {
	if cmd == "version" {
		return a.version()
	}

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
	case "import":
		return a.importF(arg)
	case "export":
		return a.export(arg)
	case "add":
		return a.add()
	case "rm":
		return a.rm()
	case "qr":
		return a.qr(arg)
	case "passwd":
		return a.changePassword()
	}
	return errors.Errorf("unknown command %q", cmd)
}

func home() string {
	u, err := user.Current()
	if err != nil {
		return os.Getenv("HOME")
	}
	return u.HomeDir
}

func main() {
	a := app{file: fmt.Sprintf("%s/.2f", home())}
	flag.StringVar(&a.file, "f", a.file, "file to store data")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "unexpected arguments")
		fmt.Fprintln(os.Stderr, "usage: 2f [-f file] list|add|rm|qr|passwd|import|export|version")
		flag.PrintDefaults()
	}
	flag.Parse()
	cmd := "list"
	if len(flag.Args()) > 0 {
		cmd = flag.Arg(0)
	}
	if err := a.run(cmd, flag.Arg(1)); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
