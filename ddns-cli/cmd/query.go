/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	lib "github.com/johanix/gen-notify-test/lib"
)

var XXXqueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Send a DNS query for 'zone. NOTIFY' and present the result.",
	Run: func(cmd *cobra.Command, args []string) {
		zonename = dns.Fqdn(zonename)
		rrs, err := lib.NotifyQuery(zonename, lib.Global.IMR)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if len(rrs) == 0 {
			fmt.Printf("No '%s NOTIFY' RR found\n", zonename)
		} else {
			for _, nr := range rrs {
				fmt.Printf("%s\n", nr.String())
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(lib.QueryCmd)
//	queryCmd.PersistentFlags().StringVarP(&zonename, "zone", "z", "", "Zone to query for the NOTIFY RRset in")
}

func xxxNotifyQuery(z string) ([]*dns.PrivateRR, error) {
	m := new(dns.Msg)
	m.SetQuestion(z, lib.TypeNOTIFY)

	if lib.Global.Debug {
		fmt.Printf("TypeNOTIFY=%d\n", lib.TypeNOTIFY)
		fmt.Printf("DEBUG: Query:\n%s\n", m.String())
	}

	res, err := dns.Exchange(m, imr)

	if err != nil && !lib.Global.Debug {
		log.Fatalf("Error from dns.Exchange(%s, NOTIFY): %v", z, err)
	}

	if res.Rcode != dns.RcodeSuccess {
		log.Fatalf("Error: Query for %s NOTIFY received rcode: %s",
			z, dns.RcodeToString[res.Rcode])
	}

	var prrs []*dns.PrivateRR

	if len(res.Answer) > 0 {
		for _, rr := range res.Answer {
			if prr, ok := rr.(*dns.PrivateRR); ok {
				if lib.Global.Debug {
					fmt.Printf("Looking up %s NOTIFY RRset:\n%s\n", z, rr.String())
				}

				if _, ok := prr.Data.(*lib.NOTIFY); ok {
					prrs = append(prrs, prr)
				} else {
					log.Fatalf("Error: answer is not a NOTIFY RR: %s", rr.String())
				}
			} else if _, ok = rr.(*dns.RRSIG); ok {
				// ignore RRSIGs for the moment
			} else {
				log.Fatalf("Error: answer is not an SRV RR: %s", rr.String())
			}
		}
	}
	return prrs, nil
}
