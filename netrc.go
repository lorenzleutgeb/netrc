package netrc

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"syscall"
)

// Holds one entry of .netrc as a tuple of login name, password and account name.
type Entry struct {
	Login, Password, Account string
	// Flag used to see whether the formatting is needed
	// or not when saving the data
	IsParsed bool
}

type Netrc struct {
	Entries map[string]Entry
}

// Gives the location of .netrc according to convention
func Location() string {
	location := ".netrc"

	if runtime.GOOS == "windows" {
		location = "_netrc"
	}

	return os.ExpandEnv("$HOME") + string(os.PathSeparator) + location
}

func CheckPermissions(fileName string) error {
	info, err := os.Stat(fileName)
	if err == nil {
		mode := info.Mode()
		if mode != 0600 {
			return fmt.Errorf("Refused to touch", fileName, "with unacceptable permissions", mode)
		}
	} else if e, ok := err.(*os.PathError); !ok || e.Err != syscall.ENOENT {
		return err
	}
	return nil
}

// Reads .netrc from it's default location
func Parse() (*Netrc, error) {
	fileName := Location()

	if err := CheckPermissions(fileName); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(fileName, os.O_RDONLY|os.O_CREATE, 0600)

	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)

	hostname := ""
	var entry *Entry = nil

	netrc := &Netrc{Entries: map[string]Entry{}}
	for scanner.Scan() {
		token := scanner.Text()

		switch token {
		case "default":
			if entry != nil {
				netrc.Entries[hostname] = *entry
			}
			entry = new(Entry)
			hostname = ""
		case "machine":
			if entry != nil {
				netrc.Entries[hostname] = *entry
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

		// Set the flag that the entry was just parsed from file
		// This way, when saving the entries, the formatting is 
		// skipped if the entry was read from file
		entry.IsParsed = true;
	}

	// catch the last entry
	if entry != nil {
		netrc.Entries[hostname] = *entry
	}

	return netrc, scanner.Err()
}

// Writes back .netrc to disk
func (netrc Netrc) Save() error {
	// Use O_APPEND flag to write at the end of file
	file, err := os.OpenFile(Location(), os.O_APPEND|os.O_WRONLY, 0600)

	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)


	for key, value := range netrc.Entries {
		if (value.IsParsed) {
			continue
		}
		if key == "" {
			writer.WriteString("\ndefault\n")
		} else {
			writer.WriteString("\nmachine " + key + "\n")
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
	}

	writer.Flush()

	return nil
}