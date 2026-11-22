package main

import (
	"fmt"
	"log"
	"net/netip"
	"strings"

	"github.com/Yuu518/sing-box-rules/lib"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(lookupCmd)
	lookupCmd.PersistentFlags().StringP("config", "c", "config.json", "URI of the JSON/HuJSON config file")
	lookupCmd.PersistentFlags().StringSliceP("search", "s", nil, "Limit lookup to specific rule list names")
}

var lookupCmd = &cobra.Command{
	Use:   "lookup [domain-or-ip...]",
	Short: "Lookup which rule lists match the given domains or IP/CIDRs after running input steps",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		configFile, _ := cmd.Flags().GetString("config")
		searchList, _ := cmd.Flags().GetStringSlice("search")

		instance, err := lib.NewInstance()
		if err != nil {
			log.Fatal(err)
		}
		if err := instance.InitConfig(configFile); err != nil {
			log.Fatal(err)
		}

		container := lib.NewContainer()
		if err := instance.RunInput(container); err != nil {
			log.Fatal(err)
		}

		for _, query := range args {
			query = strings.TrimSpace(query)
			if query == "" {
				continue
			}
			if isIPOrCIDR(query) {
				matched, ok, err := container.LookupIP(query, searchList...)
				if err != nil {
					log.Printf("lookup %s error: %v", query, err)
					continue
				}
				if ok {
					fmt.Printf("%s -> [IP] %s\n", query, strings.Join(matched, ", "))
				} else {
					fmt.Printf("%s -> [IP] (no match)\n", query)
				}
				continue
			}

			matched, ok := container.LookupDomain(query, searchList...)
			if ok {
				fmt.Printf("%s -> [DOMAIN] %s\n", query, strings.Join(matched, ", "))
			} else {
				fmt.Printf("%s -> [DOMAIN] (no match)\n", query)
			}
		}
	},
}

func isIPOrCIDR(s string) bool {
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}
