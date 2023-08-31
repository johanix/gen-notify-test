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
var pzone, childpri, parpri string

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Send a DDNS update to sync parent delegation info with child data",
	Run: func(cmd *cobra.Command, args []string) {
	        if lib.Zonename == "" {
		   log.Fatalf("Error: child zone name not specified.")
		}
		lib.Zonename = dns.Fqdn(lib.Zonename)

		if pzone == "" {
		   log.Fatalf("Error: parent zone name not specified.")
		}
		pzone = dns.Fqdn(pzone)
		
	        if childpri == "" {
		   log.Fatalf("Error: child primary nameserver not specified.")
		}
	        if parpri == "" {
		   log.Fatalf("Error: parent primary nameserver not specified.")
		}

		ns_parent, err := lib.AuthQuery(lib.Zonename, parpri, dns.TypeNS)
		if err != nil {
		   log.Fatalf("Error: looking up child %s NS RRset in parent primary %s: %v",
		   		      lib.Zonename, parpri, err)
		}

		ns_child, err := lib.AuthQuery(lib.Zonename, childpri, dns.TypeNS)
		if err != nil {
		   log.Fatalf("Error: looking up child %s NS RRset in child primary %s: %v",
		   		      lib.Zonename, childpri, err)
		}

		fmt.Printf("%d NS RRs from parent, %d NS RRs from child\n", len(ns_parent), len(ns_child))
		if lib.Global.Debug {
		for _, nsp := range ns_parent {
		    fmt.Printf("Parent: %s\n", nsp.String())
		}

		for _, nsc := range ns_child {
		    fmt.Printf("Child:  %s\n", nsc.String())
		}
		}

		differ, adds, removes := lib.RRsetDiffer(lib.Zonename, ns_child, ns_parent, dns.TypeNS, log.Default())
		if differ {
		   fmt.Printf("Parent and child NS RRsets differ:\n")
		   for _, rr := range removes {
		       fmt.Printf("Remove: %s\n", rr.String())
		   }
		   for _, rr := range adds {
		       fmt.Printf("Add:   %s\n", rr.String())
		   }
		}

		const update_scheme = 2
		dsynctarget, err := lib.LookupDSYNCTarget(pzone, parpri, dns.StringToType["ANY"], update_scheme)
		if err != nil {
		   log.Fatalf("Error from LookupDDNSTarget(%s, %s): %v", pzone, parpri, err)
		}

		err = SendUpdate(lib.Zonename, adds, removes, dsynctarget)
		if err != nil {
		   log.Fatalf("Error from SendUpdate(%v): %v", dsynctarget, err)
		}
	},
}

func init() {
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(lib.ToRFC3597Cmd)

	rootCmd.PersistentFlags().StringVarP(&lib.Zonename, "zone", "z", "", "Child zone to sync via DDNS")
	syncCmd.PersistentFlags().StringVarP(&pzone, "pzone", "Z", "", "Parent zone to sync via DDNS")
	syncCmd.PersistentFlags().StringVarP(&childpri, "primary", "p", "", "Address:port of child primary namserver")
	syncCmd.PersistentFlags().StringVarP(&parpri, "pprimary", "P", "", "Address:port of parent primary nameserver")
	syncCmd.PersistentFlags().StringVarP(&lib.Global.IMR, "imr", "i", "", "IMR to send the query to")
}

// func SendUpdate(zonename string, adds []dns.RR, removes []dns.RR, target lib.DDNSTarget) error {
func SendUpdate(zonename string, adds []dns.RR, removes []dns.RR, target lib.DSYNCTarget) error {
        var lookupzone string
	if zonename == "." {
		fmt.Printf("Error: zone name not specified. Terminating.\n")
		os.Exit(1)
	}

	for _, dst := range target.Addresses {
		if lib.Global.Verbose {
			fmt.Printf("Sending DDNS update to %s on address %s:%d\n", target.Name, dst, target.Port)
		}

		m := new(dns.Msg)
		m.SetUpdate(lookupzone)

		// remove SOA, add ntype
		// m.Question = []dns.Question{ dns.Question{zonename, notify_type, dns.ClassINET} } 

		if lib.Global.Debug {
			fmt.Printf("Sending Update:\n%s\n", m.String())
		}

		dst = net.JoinHostPort(dst, fmt.Sprintf("%d", target.Port))
		res, err := dns.Exchange(m, dst)
		if err != nil {
			log.Fatalf("Error from dns.Exchange(%s, UPDATE): %v", dst, err)
		}

		if res.Rcode != dns.RcodeSuccess {
		   	if lib.Global.Verbose {
			   fmt.Printf("... and got rcode %s back (bad)\n", dns.RcodeToString[res.Rcode])
			}
			log.Printf("Error: Rcode: %s", dns.RcodeToString[res.Rcode])
		} else {
			if lib.Global.Verbose {
				fmt.Printf("... and got rcode NOERROR back (good)\n")
			}
			break
		}
	}
	return nil
}

