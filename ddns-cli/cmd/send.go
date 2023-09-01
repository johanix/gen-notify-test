/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
        "crypto"
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

		var keyrr *dns.KEY
		var cs crypto.Signer
		var rr dns.RR

	        if keyfile != "" {
		   var ktype string
		   var err error
		   _, cs, rr, ktype, err = lib.ReadKey(keyfile)
		   if err != nil {
		      log.Fatalf("Error reading key '%s': %v", keyfile, err)
		   }

		   if ktype != "KEY" {
		      log.Fatalf("Key must be a KEY RR")
		   }

		   keyrr = rr.(*dns.KEY)
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
		   fmt.Printf("Parent and child NS RRsets differ. To get parent in sync:\n")
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

		msg, err := CreateUpdate(pzone, adds, removes)
		if err != nil {
		   log.Fatalf("Error from SendUpdate(%v): %v", dsynctarget, err)
		}

		if keyfile != "" {
		   fmt.Printf("Signing update.\n")
		   msg, err = lib.SignMsgNG(msg, lib.Zonename, cs, keyrr)
		   if err != nil {
		      log.Fatalf("Error from SendUpdate(%v): %v", dsynctarget, err)
		   }
		} else {
		      fmt.Printf("Keyfile not specified, not signing message.\n")
		}

		err = SendUpdate(msg, pzone, dsynctarget)
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

func SendUpdate(msg dns.Msg, zonename string, target lib.DSYNCTarget) error {
	if zonename == "." {
		fmt.Printf("Error: zone name not specified. Terminating.\n")
		os.Exit(1)
	}

	for _, dst := range target.Addresses {
		if lib.Global.Verbose {
			fmt.Printf("Sending DDNS update for parent zone %s to %s on address %s:%d\n", zonename, target.Name, dst, target.Port)
		}

		if lib.Global.Debug {
			fmt.Printf("Sending Update:\n%s\n", msg.String())
		}

		dst = net.JoinHostPort(dst, fmt.Sprintf("%d", target.Port))
		res, err := dns.Exchange(&msg, dst)
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

func CreateUpdate(zonename string, adds, removes []dns.RR) (dns.Msg, error) {
	if zonename == "." {
		fmt.Printf("Error: zone name not specified. Terminating.\n")
		os.Exit(1)
	}

	m := new(dns.Msg)
	m.SetUpdate(zonename)

	m.Remove(removes)
	m.Insert(adds)
		
	if lib.Global.Debug {
		fmt.Printf("Creating update msg:\n%s\n", m.String())
	}
	return *m, nil
}

