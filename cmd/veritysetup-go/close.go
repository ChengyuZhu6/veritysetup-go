package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	verity "github.com/ChengyuZhu6/veritysetup-go/pkg/verity"
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
	if err := verity.VerityClose(name); err != nil {
		return err
	}

	fmt.Printf("/dev/mapper/%s removed\n", name)
	return nil
}
