/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	lib "github.com/johanix/gen-notify-test/lib"
)

func init() {
	rootCmd.AddCommand(lib.QueryCmd)
}

