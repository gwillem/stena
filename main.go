// Command stena logs in to and scans the Nowhere Networks captive portal.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	flags "github.com/jessevdk/go-flags"
)

type loginCommand struct {
	Positional struct {
		Code string `positional-arg-name:"code" required:"yes" description:"voucher code"`
	} `positional-args:"yes"`

	LogoutOldest bool `long:"logout-oldest" description:"log out the client that is already using the voucher"`
}

// Execute logs in with a voucher and prints the resulting session.
func (l *loginCommand) Execute([]string) error {
	_, gateway, err := Device()
	if err != nil {
		return err
	}
	log.Printf("using default gateway %s", gateway)

	info, err := Detect(gateway)
	if err != nil {
		return err
	}

	if err := Login(info.Mac, info.ZoneID, l.Positional.Code, l.LogoutOldest); err != nil {
		if errors.Is(err, ErrVoucherInUse) {
			return fmt.Errorf("voucher %s is in use on another client; retry with --logout-oldest to log it out", l.Positional.Code)
		}
		return err
	}

	if err := TriggerAuth(info.AccessControllerIP); err != nil {
		return err
	}

	body, err := FetchSession(info.Mac, info.ZoneID)
	if err != nil {
		return err
	}

	var s Session
	if err := json.Unmarshal(body, &s); err != nil {
		return err
	}
	fmt.Println(s.Line(info.Mac))
	return nil
}

func main() {
	os.Exit(runCLI(os.Args[1:]))
}

func runCLI(args []string) int {
	var options struct {
		Verbose bool `short:"v" long:"verbose" description:"show diagnostic messages"`
	}
	log.SetOutput(io.Discard)
	parser := flags.NewParser(&options, flags.Default)
	parser.Name = "stena"
	parser.CommandHandler = func(command flags.Commander, args []string) error {
		if options.Verbose {
			log.SetOutput(os.Stderr)
		}
		if len(args) != 0 {
			return fmt.Errorf("unexpected arguments: %s", strings.Join(args, " "))
		}
		if command != nil {
			return command.Execute(args)
		}
		return nil
	}
	if _, err := parser.AddCommand("login", "Log in with a voucher code",
		"Discover the captive portal and authenticate this client with a voucher code.", &loginCommand{}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := parser.AddCommand("scan", "Show sessions for clients in the ARP cache",
		"Discover the captive portal, save session JSON in the working directory, and print session and traffic summaries.", &scanCommand{}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := parser.ParseArgs(args); err != nil {
		var flagError *flags.Error
		if errors.As(err, &flagError) && flagError.Type == flags.ErrHelp {
			return 0
		}
		return 1
	}
	return 0
}
