//go:build linux

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
	return nil
}
