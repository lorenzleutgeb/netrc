package netrc

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tcs := []struct {
		content string
		machine string
		err     error
		want    Entry
	}{
		{`machine mail.google.com
	login joe@gmail.com
	account gmail
	password somethingSecret`, "mail.google.com", nil, Entry{"joe@gmail.com", "somethingSecret", "gmail"}},
		{`machine ray login demo password mypassword`, "ray", nil, Entry{"demo", "mypassword", ""}},
		{`
machine ray login demo password mypassword
default
	login anonymous
password joe@example.com`, "", nil, Entry{"anonymous", "joe@example.com", ""}},
		{`machine ray login demo password mypassword
machine ray2 login demo password mypassword`, "ray", nil, Entry{"demo", "mypassword", ""}},
		{`macdef allput`, "", errors.New("Not support macro definition."), Entry{}},
	}
	for _, tc := range tcs {
		t.Run("", func(t *testing.T) {
			r := strings.NewReader(tc.content)
			entries, err := parse(r)
			if tc.err == nil || err == nil {
				if err != tc.err {
					t.Fatal(err, tc.err)
				}
			} else {
				if err.Error() != tc.err.Error() {
					t.Fatal(err, tc.err)
				}
			}
			entry := entries[tc.machine]
			if entry != tc.want {
				t.Fatal(entry, tc.want)
			}
		})
	}
}

func TestSave(t *testing.T) {
	tcs := []struct {
		entries Entries
		want    string
	}{
		{
			Entries{
				"mail.google.com": Entry{"joe@example.com", "mypassword", "gmail"},
			},
			`machine mail.google.com
	account gmail
	login joe@example.com
	password mypassword

`},
		{
			Entries{
				"": Entry{"anonymous", "joe@example.com", ""},
			},
			`default
	login anonymous
	password joe@example.com

`},
	}

	for _, tc := range tcs {
		t.Run("", func(t *testing.T) {
			buf := bytes.NewBuffer([]byte{})
			w := bufio.NewWriter(buf)
			err := tc.entries.save(w)
			if err != nil {
				t.Fatal(err)
			}
			content := string(buf.Bytes())
			if content != tc.want {
				t.Fatal(content, tc.want)
			}
		})
	}
}
