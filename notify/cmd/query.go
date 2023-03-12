/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Send a DNS query for 'zone. NOTIFY' and present the result.",
	Run: func(cmd *cobra.Command, args []string) {
		zonename = dns.Fqdn(zonename)
		rrs, err := NotifyQuery(zonename)
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
	rootCmd.AddCommand(queryCmd)
	queryCmd.PersistentFlags().StringVarP(&zonename, "zone", "z", "", "Zone to query for the NOTIFY RRset in")
}

func NotifyQuery(z string) ([]*dns.PrivateRR, error) {
	m := new(dns.Msg)
	m.SetQuestion(z, TypeNOTIFY)

	if debug {
		fmt.Printf("TypeNOTIFY=%d\n", TypeNOTIFY)
		fmt.Printf("DEBUG: Query:\n%s\n", m.String())
	}

	res, err := dns.Exchange(m, imr)

	if err != nil && !debug {
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
				if debug {
					fmt.Printf("Looking up parent NOTIFY RRset:\n%s\n", rr.String())
				}

				if _, ok := prr.Data.(*NOTIFY); ok {
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
