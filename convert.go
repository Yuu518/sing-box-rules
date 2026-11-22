package main

import (
	"log"

	"github.com/Yuu518/sing-box-rules/lib"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(convertCmd)
	convertCmd.PersistentFlags().StringP("config", "c", "config.json", "URI of the JSON/HuJSON config file (local path, HTTP(S) URL, or s3:// URI)")
}

var convertCmd = &cobra.Command{
	Use:     "convert",
	Aliases: []string{"conv"},
	Short:   "Build and convert rule-sets according to a config file",
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		log.Println("Use config:", configFile)

		instance, err := lib.NewInstance()
		if err != nil {
			log.Fatal(err)
		}

		if err := instance.InitConfig(configFile); err != nil {
			log.Fatal(err)
		}

		if err := instance.Run(); err != nil {
			log.Fatal(err)
		}
	},
}
