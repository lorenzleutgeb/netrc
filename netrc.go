package netrc

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"syscall"
)

// Entry holds one entry of .netrc as a tuple of login name, password and account name.
type Entry struct {
	Login, Password, Account string
}

// Entries maps a machine name to an Entry.
type Entries map[string]Entry

// Location gives the location of .netrc according to convention.
func Location() string {
	location := ".netrc"
	if runtime.GOOS == "windows" {
		location = "_netrc"
	}

	return os.ExpandEnv("$HOME") + string(os.PathSeparator) + location
}

func checkPermissions(fileName string) error {
	info, err := os.Stat(fileName)
	if err == nil {
		mode := info.Mode()
		if mode != 0600 {
			return fmt.Errorf("netrc: refused to touch %s with unacceptable permissions %v", fileName, mode)
		}
	} else if e, ok := err.(*os.PathError); !ok || e.Err != syscall.ENOENT {
		return err
	}
	return nil
}

// Parse reads .netrc from it's default location
func Parse() (Entries, error) {
	fileName := Location()

	if err := checkPermissions(fileName); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0600)

	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)

	hostname := ""
	var entry *Entry

	netrc := Entries{}
	for scanner.Scan() {
		token := scanner.Text()

		switch token {
		case "default":
			if entry != nil {
				netrc[hostname] = *entry
			}
			entry = new(Entry)
			hostname = ""
		case "machine":
			if entry != nil {
				netrc[hostname] = *entry
			}
			entry = new(Entry)
			scanner.Scan()
			hostname = scanner.Text()
		case "password":
			scanner.Scan()
			entry.Password = scanner.Text()
		case "login":
			scanner.Scan()
			entry.Login = scanner.Text()
		case "account":
			scanner.Scan()
			entry.Account = scanner.Text()
		case "macdef":
			return nil, fmt.Errorf(fileName, "contains at least one macro definition. This is currently not supported giving up.")
		}
	}

	// catch the last entry
	if entry != nil {
		netrc[hostname] = *entry
	}

	return netrc, scanner.Err()
}

// Save writes back .netrc to disk
func (netrc Entries) Save() error {
	file, err := os.OpenFile(Location(), os.O_WRONLY|os.O_TRUNC, 0600)

	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for key, value := range netrc {
		if key == "" {
			writer.WriteString("default\n")
		} else {
			writer.WriteString("machine " + key + "\n")
		}

		if value.Account != "" {
			writer.WriteString("\taccount " + value.Account + "\n")
		}
		if value.Login != "" {
			writer.WriteString("\tlogin " + value.Login + "\n")
		}
		if value.Password != "" {
			writer.WriteString("\tpassword " + value.Password + "\n")
		}

		writer.WriteString("\n")
	}

	writer.Flush()

	return nil
}
