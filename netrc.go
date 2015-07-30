package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"regexp"
	"strings"
)

// Holds one entry of .netrc as a tuple of login name, password and account name.
type Entry struct {
	Login, Password, Account, PrintFormat string
}

type Netrc struct {
	Entries map[string]Entry
}

// Keywords to be searched for inside the .netrc file
var keywords = [...]string{"default", "machine", "password", "login", "account", "macdef"}

// Gives the location of .netrc according to convention
func Location() string {
	location := ".netrc"

	if runtime.GOOS == "windows" {
		location = "_netrc"
	}

	//return os.ExpandEnv("$HOME") + string(os.PathSeparator) + location
	return "D:" + string(os.PathSeparator) + location
}

func checkPermissions(fileName string) error {
	info, err := os.Stat(fileName)
	if err == nil {
		mode := info.Mode()
		//if mode != 0600 {
		if mode != 0666 {
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

	if err := checkPermissions(fileName); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(fileName, os.O_RDONLY|os.O_CREATE, 0600)

	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Read line by line instead of word by word
	scanner.Split(bufio.ScanLines)

	hostname := ""
	var entry *Entry = nil

	netrc := &Netrc{Entries: map[string]Entry{}}
	for scanner.Scan() {
		line := scanner.Text()

		// Foreach keyword try to find it on the current read line
		for _, keyword := range keywords {
			re := regexp.MustCompile(keyword + ` ([^ ]+)\n?`)

			res := re.FindStringSubmatch(line)

			if (len(res) == 0) {
				continue
			}

			// If the line contains the searched keyword
			// then extract data to entry
			switch keyword {
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
				hostname = res[1]
			case "password":
				entry.Password = res[1]
			case "login":
				entry.Login = res[1]
			case "account":
				entry.Account = res[1]
			case "macdef":
				return nil, fmt.Errorf(fileName, "contains at least one macro definition. This is currently not supported giving up.")
			}

			// Generate format string that will be used for printing
			// for current row or update it
			line = strings.Replace(line, res[1], "%s", 1)
		}

		// Save format string to entry
		entry.PrintFormat = entry.PrintFormat + line + "\n"
	}

	// catch the last entry
	if entry != nil {
		netrc.Entries[hostname] = *entry
	}

	return netrc, scanner.Err()
}

// Writes back .netrc to disk
func (netrc Netrc) Save() error {
	file, err := os.OpenFile(Location(), os.O_WRONLY|os.O_TRUNC, 0600)

	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for key, value := range netrc.Entries {
		// If the entry has been parsed there is a
		// print format string that we should use
		if (value.PrintFormat != "") {
			values := []interface{}{key}
			// Append the values that are not empty
			if (value.Account != "") {
				values = append(values, value.Account)
			}
			if (value.Login != "") {
				values = append(values, value.Login)
			}
			if (value.Password != "") {
				values = append(values, value.Password)
			}
			// Generate string from format and values
			result := fmt.Sprintf(value.PrintFormat, values...)
			writer.WriteString(result)
		} else {
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
		}
	}

	writer.Flush()

	return nil
}

func main() {
	var netrc, _ = Parse()

	var entry *Entry = nil
	entry = new(Entry)
	entry.Password = "testpass"
	entry.Login = "testlogin"
	netrc.Entries["test"] = *entry

	netrc.Save()
}