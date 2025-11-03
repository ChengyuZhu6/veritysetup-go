package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "format":
		p, dataPath, hashPath, err := parseFormatArgs(os.Args[2:])
		if err != nil {
			usage()
			log.Fatalf("format: %v", err)
		}
		if err := runFormat(p, dataPath, hashPath); err != nil {
			log.Fatalf("format: %v", err)
		}
	case "verify":
		p, dataPath, hashPath, rootDigest, err := parseVerifyArgs(os.Args[2:])
		if err != nil {
			usage()
			log.Fatalf("verify: %v", err)
		}
		if err := runVerify(p, dataPath, hashPath, rootDigest); err != nil {
			log.Fatalf("verify: %v", err)
		}
	case "open":
		p, dataDev, name, hashDev, rootDigest, flags, err := parseOpenArgs(os.Args[2:])
		if err != nil {
			usage()
			log.Fatalf("open: %v", err)
		}
		if name == "" || strings.Contains(name, "/") {
			log.Fatalf("open: %v", err)
		}

		if err := runOpen(p, dataDev, name, hashDev, rootDigest, flags); err != nil {
			log.Fatalf("open: %v", err)
		}
	case "close":
		name, err := parseCloseArgs(os.Args[2:])
		if err != nil {
			usage()
			log.Fatalf("close: %v", err)
		}
		if err := runClose(name); err != nil {
			log.Fatalf("close: %v", err)
		}
	case "status":
		name, err := parseStatusArgs(os.Args[2:])
		if err != nil {
			usage()
			log.Fatalf("status: %v", err)
		}
		if err := runStatus(name); err != nil {
			log.Fatalf("status: %v", err)
		}
	case "dump":
		path, err := parseDumpArgs(os.Args[2:])
		if err != nil {
			usage()
			log.Fatalf("dump: %v", err)
		}
		if err := runDump(path); err != nil {
			log.Fatalf("dump: %v", err)
		}
	case "-h", "--help", "help":
		usage()
	default:
		log.Fatalf("unknown subcommand: %s", cmd)
	}
}

func usage() {
	prog := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  %s format [options] <data_path> <hash_path>\n", prog)
	fmt.Fprintf(os.Stderr, "  %s verify [options] <data_path> <hash_path> <root_hex>\n", prog)
	fmt.Fprintf(os.Stderr, "  %s open   [options] <data_dev> <name> <hash_dev> <root_hex>\n", prog)
	fmt.Fprintf(os.Stderr, "  %s close  <name>\n", prog)
	fmt.Fprintf(os.Stderr, "  %s status <name>\n", prog)
	fmt.Fprintf(os.Stderr, "\nFormat options:\n")
	fmt.Fprintf(os.Stderr, "  --hash <sha1|sha256|sha512>        Hash algorithm (default sha256)\n")
	fmt.Fprintf(os.Stderr, "  --data-block-size <bytes>          Data block size (default 4096)\n")
	fmt.Fprintf(os.Stderr, "  --hash-block-size <bytes>          Hash block size (default 4096)\n")
	fmt.Fprintf(os.Stderr, "  --format <0|1>                     Format type (1 - normal, 0 - original Chrome OS)\n")
	fmt.Fprintf(os.Stderr, "  --salt <hex|->                     Salt as hex or '-' for none\n")
	fmt.Fprintf(os.Stderr, "  --uuid <uuid>                      UUID (e.g. 123e4567-e89b-12d3-a456-426614174000)\n")
	fmt.Fprintf(os.Stderr, "  --data-blocks <n>                  Data blocks (override file size)\n")
	fmt.Fprintf(os.Stderr, "  --no-superblock                    Do not write superblock\n")
	fmt.Fprintf(os.Stderr, "  --hash-offset <bytes>              Hash area offset (when --no-superblock)\n")
	fmt.Fprintf(os.Stderr, "\nVerify options:\n")
	fmt.Fprintf(os.Stderr, "  --hash <sha1|sha256|sha512>        Hash algorithm (default sha256)\n")
	fmt.Fprintf(os.Stderr, "  --data-block-size <bytes>          Data block size (default 4096)\n")
	fmt.Fprintf(os.Stderr, "  --hash-block-size <bytes>          Hash block size (default 4096)\n")
	fmt.Fprintf(os.Stderr, "  --salt <hex|->                     Salt as hex or '-' (overrides superblock)\n")
	fmt.Fprintf(os.Stderr, "  --data-blocks <n>                  Data blocks (override file size)\n")
	fmt.Fprintf(os.Stderr, "  --no-superblock                    Hash file has no superblock\n")
	fmt.Fprintf(os.Stderr, "  --hash-offset <bytes>              Hash area offset (when --no-superblock)\n")
	fmt.Fprintf(os.Stderr, "  --uuid <uuid>                      UUID (ignored unless --no-superblock)\n")
	fmt.Fprintf(os.Stderr, "\nOpen options (Linux only):\n")
	fmt.Fprintf(os.Stderr, "  --hash <sha1|sha256|sha512>        Hash algorithm (default sha256)\n")
	fmt.Fprintf(os.Stderr, "  --data-block-size <bytes>          Data block size (default 4096)\n")
	fmt.Fprintf(os.Stderr, "  --hash-block-size <bytes>          Hash block size (default 4096)\n")
	fmt.Fprintf(os.Stderr, "  --salt <hex|->                     Salt as hex or '-'\n")
	fmt.Fprintf(os.Stderr, "  --data-blocks <n>                  Data blocks (override device size)\n")
	fmt.Fprintf(os.Stderr, "  --no-superblock                    Hash device has no superblock\n")
	fmt.Fprintf(os.Stderr, "  --hash-offset <bytes>              Hash area offset (when --no-superblock)\n")
}
