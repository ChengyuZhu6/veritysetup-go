/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	dm "github.com/containerd/go-dmverity/pkg/dm"
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
