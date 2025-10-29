//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	dm "github.com/ChengyuZhu6/veritysetup-go/pkg/dm"
)

func parseCloseArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("close", flag.ContinueOnError)
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

func runClose(name string) error {
	c, err := dm.Open()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.RemoveDevice(name); err != nil {
		return err
	}
	fmt.Printf("/dev/mapper/%s removed\n", name)
	return nil
}
