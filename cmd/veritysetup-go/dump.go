package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ChengyuZhu6/veritysetup-go/pkg/verity"
)

func parseDumpArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("dump", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	if err := fs.Parse(args); err != nil {
		return "", err
	}

	if fs.NArg() != 1 {
		return "", fmt.Errorf("dump requires exactly one argument: <hash_device>")
	}

	return fs.Arg(0), nil
}

func runDump(hashPath string) error {
	output, err := verity.DumpDevice(hashPath)
	if err != nil {
		return err
	}

	fmt.Print(output)
	return nil
}
