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

		ns_child, err := lib.AuthQuery(lib.Zonename, parpri, dns.TypeNS)
		if err != nil {
		   log.Fatalf("Error: looking up child %s NS RRset in child primary %s: %v",
		   		      lib.Zonename, childpri, err)
		}

		for _, ns := range ns_parent {
		    fmt.Printf("Parent: %s\n", ns.String())
		}
		for _, ns := range ns_child {
		    fmt.Printf("Child:  %s\n", ns.String())
		}

		SendUpdate(dns.Fqdn(lib.Zonename), []dns.RR{}, []dns.RR{})
	},
}

func init() {
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(lib.ToRFC3597Cmd)

	rootCmd.PersistentFlags().StringVarP(&lib.Zonename, "zone", "z", "", "Child zone to sync via DDNS")
	syncCmd.PersistentFlags().StringVarP(&pzone, "pzone", "Z", "", "Parent zone to sync via DDNS")
	syncCmd.PersistentFlags().StringVarP(&childpri, "primary", "p", "", "Address:port of child primary namserver")
	syncCmd.PersistentFlags().StringVarP(&parpri, "pprimary", "P", "", "Address:port of parent primary nameserver")
}

func SendUpdate(zonename string, adds []dns.RR, removes []dns.RR) {
        var lookupzone string
	if zonename == "." {
		fmt.Printf("Error: zone name not specified. Terminating.\n")
		os.Exit(1)
	}

	lookupzone = lib.ParentZone(zonename, lib.Global.IMR)
	
	const update_scheme = 2

	prrs, err := lib.NotifyQuery(lookupzone, lib.Global.IMR)

	found := false
	var dsync_rr *dns.PrivateRR

	for _, prr := range prrs {
		if prr.Data.(*lib.NOTIFY).Scheme == update_scheme {
			found = true
			dsync_rr = prr
			break
		}
	}
	if !found {
		fmt.Printf("No DDNS update destination found for for zone %s parent. Ignoring.\n",
			zonename)
		os.Exit(1)
	}

	dsync, _ := dsync_rr.Data.(*lib.NOTIFY)

	if lib.Global.Verbose {
		fmt.Printf("Looked up published DDNS update address for zone %s:\n\n%s\n\n",
			zonename, dsync_rr.String())
	}

	dest_addrs, err := net.LookupHost(dsync.Dest)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	if lib.Global.Verbose {
	   fmt.Printf("%s has the IP addresses: %v\n", dsync.Dest, dest_addrs)
	}

	for _, dst := range dest_addrs {
		if lib.Global.Verbose {
			fmt.Printf("Sending DDNS update to %s on address %s:%d\n", dsync.Dest, dst, dsync.Port)
		}

		m := new(dns.Msg)
		m.SetUpdate(lookupzone)

		// remove SOA, add ntype
		// m.Question = []dns.Question{ dns.Question{zonename, notify_type, dns.ClassINET} } 

		if lib.Global.Debug {
			fmt.Printf("Sending Update:\n%s\n", m.String())
		}

		dst = net.JoinHostPort(dst, fmt.Sprintf("%d", dsync.Port))
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
}

