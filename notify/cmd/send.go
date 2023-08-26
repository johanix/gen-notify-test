/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"

	lib "github.com/johanix/gen-notify-test/lib"
)

var zonename string
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

func init() {
	rootCmd.AddCommand(sendCmd)
	sendCmd.AddCommand(sendCdsCmd, sendCsyncCmd, sendDnskeyCmd, sendSoaCmd)
	rootCmd.AddCommand(lib.ToRFC3597Cmd)

	sendCmd.PersistentFlags().StringVarP(&lib.Zonename, "zone", "z", "", "Zone to send a parent notify for")
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
		lookupzone = lib.ParentZone(zonename, lib.Global.IMR)
	}
	
	var notify_type = dns.StringToType[ntype]
	const notify_scheme = 1

	prrs, err := lib.NotifyQuery(lookupzone, lib.Global.IMR)

	found := false
	var notify_rr *dns.PrivateRR

	for _, prr := range prrs {
		if prr.Data.(*lib.NOTIFY).Scheme == notify_scheme && prr.Data.(*lib.NOTIFY).Type == notify_type {
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

	notify, _ := notify_rr.Data.(*lib.NOTIFY)

	if lib.Global.Verbose {
		fmt.Printf("Looked up published notification address for NOTIFY(%s) for zone %s:\n\n%s\n\n",
			ntype, zonename, notify_rr.String())
	}

	dest_addrs, err := net.LookupHost(notify.Dest)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if lib.Global.Verbose {
	   fmt.Printf("%s has the IP addresses: %v\n", notify.Dest, dest_addrs)
	}

	for _, dst := range dest_addrs {
		if lib.Global.Verbose {
			fmt.Printf("Sending NOTIFY(%s) to %s on address %s:%d\n",
					    notify.Dest, dst, notify.Port)
		}

		m := new(dns.Msg)
		m.SetNotify(zonename)

		// remove SOA, add ntype
		m.Question = []dns.Question{ dns.Question{zonename, notify_type, dns.ClassINET} } 

		if lib.Global.Debug {
			fmt.Printf("Sending Notify:\n%s\n", m.String())
		}

		dst = net.JoinHostPort(dst, fmt.Sprintf("%d", notify.Port))
		res, err := dns.Exchange(m, dst)
		if err != nil {
			log.Fatalf("Error from dns.Exchange(%s, NOTIFY(%s)): %v", dst, ntype, err)
		}

		if res.Rcode != dns.RcodeSuccess {
		   	if lib.Global.Verbose {
			   fmt.Printf("... and got rcode %s back (bad)\n",
			   		   dns.RcodeToString[res.Rcode])
			}
			log.Printf("Error: Rcode: %s", dns.RcodeToString[res.Rcode])
		} else {
			if lib.Global.Verbose {
				fmt.Printf("... and got rcode NOERROR back (good)\n")
			}
			break
		}
	}
}

