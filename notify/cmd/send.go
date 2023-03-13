/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var zonename, rrstr string
var imr = "8.8.8.8:53"

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "The 'notify send' command is only usable via defined sub-commands",
}

var sendCdsCmd = &cobra.Command{
	Use:   "cds",
	Short: "Send a Notify(CDS) to parent of zone",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify(dns.Fqdn(zonename), "CDS")
	},
}

var sendCsyncCmd = &cobra.Command{
	Use:   "csync",
	Short: "Send a Notify(CSYNC) to parent of zone",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify(dns.Fqdn(zonename), "CSYNC")
	},
}

var sendDnskeyCmd = &cobra.Command{
	Use:   "dnskey",
	Short: "Send a Notify(DNSKEY) to other signers of zone (multi-signer setup)",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify(dns.Fqdn(zonename), "DNSKEY")
	},
}

var sendSoaCmd = &cobra.Command{
	Use:   "soa",
	Short: "Send a normal Notify(SOA) to someone",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify(dns.Fqdn(zonename), "SOA")
	},
}

var torfc3597Cmd = &cobra.Command{
	Use:   "rfc3597",
	Short: "Generate the RFC 3597 representation of a DNS record",
	Run: func(cmd *cobra.Command, args []string) {
	        if rrstr == "" {
		   log.Fatalf("Record to generate RFC 3597 representation for not specified.")
		}
		
		rr, err := dns.NewRR(rrstr)
		if err != nil {
			log.Fatal("Could not parse record \"%s\": %v", rrstr, err)
		}

		fmt.Printf("Normal   (len=%d): \"%s\"\n", dns.Len(rr), rr.String())
		u := new(dns.RFC3597)
		u.ToRFC3597(rr)
		fmt.Printf("RFC 3597 (len=%d): \"%s\"\n", dns.Len(u), u.String())
	},
}

func init() {
	rootCmd.AddCommand(sendCmd)
	sendCmd.AddCommand(sendCdsCmd, sendCsyncCmd, sendDnskeyCmd, sendSoaCmd)
	rootCmd.AddCommand(torfc3597Cmd)

	sendCmd.PersistentFlags().StringVarP(&zonename, "zone", "z", "", "Zone to send a parent notify for")
	torfc3597Cmd.Flags().StringVarP(&rrstr, "record", "r", "", "Record to convert to RFC 3597 notation")
}

func SendNotify(zonename string, ntype string) {
        var lookupzone string
	if zonename == "." {
		fmt.Printf("Error: zone name not specified. Terminating.\n")
		os.Exit(1)
	}

	switch ntype {
	case "DNSKEY":
		lookupzone = zonename
	default:
		lookupzone = ParentZone(zonename, imr)
	}
	
	var notify_type = dns.StringToType[ntype]

	prrs, err := NotifyQuery(lookupzone)

	found := false
	var notify_rr *dns.PrivateRR

	for _, prr := range prrs {
		if prr.Data.(*NOTIFY).Type == notify_type {
			found = true
			notify_rr = prr
			break
		}
	}
	if !found {
		fmt.Printf("No notification destination found for NOTIFY(%s) for zone %s. Ignoring.\n",
			ntype, zonename)
		os.Exit(1)
	}

	notify, _ := notify_rr.Data.(*NOTIFY)

	if verbose {
		fmt.Printf("Looked up published notification address for NOTIFY(%s) for zone %s:\n\n%s\n\n",
			ntype, zonename, notify_rr.String())
	}

	dest_addrs, err := net.LookupHost(notify.Dest)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if verbose {
	   fmt.Printf("%s has the IP addresses: %v\n", notify.Dest, dest_addrs)
	}

	for _, dst := range dest_addrs {
		if verbose {
			fmt.Printf("Sending NOTIFY(%s) to %s on address %s:%d\n", ntype, notify.Dest, dst, notify.Port)
		}

		m := new(dns.Msg)
		m.SetNotify(zonename)

		// remove SOA, add ntype
		m.Question = []dns.Question{ dns.Question{zonename, notify_type, dns.ClassINET} } 

		if debug {
			fmt.Printf("Sending Notify:\n%s\n", m.String())
		}

		dst = net.JoinHostPort(dst, fmt.Sprintf("%d", notify.Port))
		res, err := dns.Exchange(m, dst)
		if err != nil {
			log.Fatalf("Error from dns.Exchange(%s, NOTIFY(%s)): %v", dst, ntype, err)
		}

		if res.Rcode != dns.RcodeSuccess {
		   	if verbose {
			   fmt.Printf("... and got rcode %s back (bad)\n", dns.RcodeToString[res.Rcode])
			}
			log.Printf("Error: Rcode: %s", dns.RcodeToString[res.Rcode])
		} else {
			if verbose {
				fmt.Printf("... and got rcode NOERROR back (good)\n")
			}
			break
		}
	}
}

func ParentZone(z, imr string) string {
	labels := strings.Split(z, ".")
	var parent string

	if len(labels) == 1 {
		return z
	} else if len(labels) > 1 {
		upone := dns.Fqdn(strings.Join(labels[1:], "."))

		m := new(dns.Msg)
		m.SetQuestion(upone, dns.TypeSOA)
		m.SetEdns0(4096, true)
		m.CheckingDisabled = true

		r, err := dns.Exchange(m, imr)
		if err != nil {
			return fmt.Sprintf("Error from dns.Exchange: %v\n", err)
		}
		if r != nil {
			if len(r.Answer) != 0 {
				parent = r.Answer[0].Header().Name
				return parent
			}
			if len(r.Ns) > 0 {
				for _, rr := range r.Ns {
					if rr.Header().Rrtype == dns.TypeSOA {
						parent = r.Ns[0].Header().Name
						return parent
					}
				}
			}

			log.Printf("ParentZone: ERROR: Failed to locate parent of '%s' via Answer and Authority. Now guessing.", z)
			return upone
		}
	}
	log.Printf("ParentZone: had difficulties splitting zone '%s'\n", z)
	return z
}
