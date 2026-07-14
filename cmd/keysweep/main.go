// Command keysweep inventories every private key and certificate on disk:
// type, bits, protection state, expiry. See README.md for usage.
package main

import (
	"os"

	"github.com/JaydenCJ/keysweep/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
