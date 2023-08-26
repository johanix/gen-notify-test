/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package lib

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

type Globals struct {
     IMR     string
     Verbose bool
     Debug   bool
}

var Global = Globals{
		IMR:		"8.8.8.8:53",
		Verbose:	false,
		Debug:		false,
    	   }

var Zonename string

var QueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Send a DNS query for 'zone. NOTIFY' and present the result.",
	Run: func(cmd *cobra.Command, args []string) {
		Zonename = dns.Fqdn(Zonename)
		rrs, err := NotifyQuery(Zonename, Global.IMR)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		if len(rrs) == 0 {
			fmt.Printf("No '%s NOTIFY' RR found\n", Zonename)
		} else {
			for _, nr := range rrs {
				fmt.Printf("%s\n", nr.String())
			}
		}
	},
}

func init() {
//	rootCmd.AddCommand(queryCmd)
	QueryCmd.PersistentFlags().StringVarP(&Zonename, "zone", "z", "", "Zone to query for the NOTIFY RRset in")
}

func NotifyQuery(z, imr string) ([]*dns.PrivateRR, error) {
	m := new(dns.Msg)
	m.SetQuestion(z, TypeNOTIFY)

	if Global.Debug {
		fmt.Printf("TypeNOTIFY=%d\n", TypeNOTIFY)
		fmt.Printf("DEBUG: Query:\n%s\n", m.String())
	}

	res, err := dns.Exchange(m, imr)

	if err != nil && !Global.Debug {
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
				if Global.Debug {
					fmt.Printf("Looking up %s NOTIFY RRset:\n%s\n", z, rr.String())
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
