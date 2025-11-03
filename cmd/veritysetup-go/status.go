package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	dm "github.com/ChengyuZhu6/veritysetup-go/pkg/dm"
)

func parseStatusArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return "", errors.New("require <name>")
	}
	return rest[0], nil
}

func runStatus(name string) error {
	c, err := dm.Open()
	if err != nil {
		return err
	}
	defer c.Close()

	st, err := c.DeviceStatus(name)
	if err != nil {
		return err
	}

	state := "inactive"
	if st.ActivePresent {
		state = "active"
	}
	fmt.Printf("/dev/mapper/%s is %s.\n", name, state)

	if st.ActivePresent {
		fmt.Printf("  type:        %s\n", "verity")
		fmt.Printf("  status:      %d:%d\n", st.Major, st.Minor)
		fmt.Printf("  open count:  %d\n", st.OpenCount)
		fmt.Printf("  event:       %d\n", st.EventNr)

		tableStatus, err := c.TableStatus(name, false)
		if err == nil && tableStatus != "" {
			fmt.Printf("  table:       %s\n", tableStatus)
		}
	}

	return nil
}
