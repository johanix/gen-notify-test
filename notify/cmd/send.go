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
		SendNotify(dns.Fqdn(lib.Zonename), "CDS")
	},
}

var sendCsyncCmd = &cobra.Command{
	Use:   "csync",
	Short: "Send a Notify(CSYNC) to parent of zone",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify(dns.Fqdn(lib.Zonename), "CSYNC")
	},
}

var sendDnskeyCmd = &cobra.Command{
	Use:   "dnskey",
	Short: "Send a Notify(DNSKEY) to other signers of zone (multi-signer setup)",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify(dns.Fqdn(lib.Zonename), "DNSKEY")
	},
}

var sendSoaCmd = &cobra.Command{
	Use:   "soa",
	Short: "Send a normal Notify(SOA) to someone",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify(dns.Fqdn(lib.Zonename), "SOA")
	},
}

func init() {
	rootCmd.AddCommand(sendCmd)
	sendCmd.AddCommand(sendCdsCmd, sendCsyncCmd, sendDnskeyCmd, sendSoaCmd)

	sendCmd.PersistentFlags().StringVarP(&lib.Zonename, "zone", "z", "", "Zone to send a parent notify for")
	sendCmd.PersistentFlags().StringVarP(&pzone, "pzone", "Z", "", "Parent zone to sync via DDNS")
	sendCmd.PersistentFlags().StringVarP(&childpri, "primary", "p", "", "Address:port of child primary namserver")
	sendCmd.PersistentFlags().StringVarP(&parpri, "pprimary", "P", "", "Address:port of parent primary nameserver")
}

var pzone, childpri, parpri string

func SendNotify(zonename string, ntype string) {
	var lookupzone, lookupserver string
	if zonename == "." {
		fmt.Printf("Error: zone name not specified. Terminating.\n")
		os.Exit(1)
	}

	if childpri == "" {
		log.Fatalf("Error: child primary nameserver not specified.")
	}

	switch ntype {
	case "DNSKEY":
		lookupzone = zonename
		lookupserver = childpri
	default:
		// lookupzone = lib.ParentZone(zonename, lib.Global.IMR)
		if pzone == "" {
			log.Fatalf("Error: parent zone name not specified.")
		}
		pzone = dns.Fqdn(pzone)

		if parpri == "" {
			log.Fatalf("Error: parent primary nameserver not specified.")
		}
		lookupzone = pzone
		lookupserver = parpri
	}

	const notify_scheme = 1
	dsynctarget, err := lib.LookupDSYNCTarget(lookupzone, lookupserver, dns.StringToType[ntype], notify_scheme)
	if err != nil {
	   log.Fatalf("Error from LookupDSYNCTarget(%s, %s): %v", lookupzone, lookupserver, err)
	}

	for _, dst := range dsynctarget.Addresses {
		if lib.Global.Verbose {
			fmt.Printf("Sending NOTIFY(%s) to %s on address %s:%d\n",
				ntype, dsynctarget.Name, dst, dsynctarget.Port)
		}

		m := new(dns.Msg)
		m.SetNotify(zonename)

		// remove SOA, add ntype
		m.Question = []dns.Question{dns.Question{zonename, dns.StringToType[ntype], dns.ClassINET}}

		if lib.Global.Debug {
			fmt.Printf("Sending Notify:\n%s\n", m.String())
		}

		dst = net.JoinHostPort(dst, fmt.Sprintf("%d", dsynctarget.Port))
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
