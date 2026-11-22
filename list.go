package main

import (
	"fmt"

	"github.com/Yuu518/sing-box-rules/lib"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(listCmd)
}

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"l", "ls"},
	Short:   "List all available input and output formats",
	Run: func(cmd *cobra.Command, args []string) {
		lib.ListInputConverter()
		fmt.Println()
		lib.ListOutputConverter()
	},
}
