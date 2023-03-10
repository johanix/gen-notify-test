/*
 *
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
	// "github.com/spf13/viper"
)

var zonename string
var imr = "8.8.8.8:53"

var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "The notify command is only usable via defined sub-commands",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			os.Exit(0)
		}

		rrmap := map[string]bool{}

		// XXX: This code is for sending multiple NOTIFY RRs in the same Query section of a
		//      NOTIFY message. That works fine in the sender end, but in the receiver end
		//      it requires a minor (4 lines or so) modification to the Golang dns package.
		//      Otherwise the reciever will return FORMERR.

		for _, arg := range args {
			if strings.Contains(arg, "+") {
				possibles := strings.Split(arg, "+")
				for _, pt := range possibles {
					switch v := strings.ToLower(pt); v {
					case "cds", "csync", "dnskey", "soa":
						rrmap[v] = true
					default:
						fmt.Printf("Error: '%s' is not a defined Notify RRtype.\n", v)
						os.Exit(1)
					}
				}

			} else {
			       fmt.Printf("Warning: arg '%s' does not contain a '+'. Terminating.\n", arg)
			       os.Exit(1)
			}
		}
		rrtypes := []string{}
		for t, _ := range rrmap {
			rrtypes = append(rrtypes, t)
		}
		SendNotify(rrtypes)
	},
}

var notifyCdsCmd = &cobra.Command{
	Use:   "cds",
	Short: "Send a Notify(CDS) to parent of zone",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify([]string{"cds"})
	},
}

var notifyCsyncCmd = &cobra.Command{
	Use:   "csync",
	Short: "Send a Notify(CSYNC) to parent of zone",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify([]string{"csync"})
	},
}

var notifyDnskeyCmd = &cobra.Command{
	Use:   "dnskey",
	Short: "Send a Notify(DNSKEY) to other signers of zone (multi-signer setup)",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify([]string{"dnskey"})
	},
}

var notifySoaCmd = &cobra.Command{
	Use:   "soa",
	Short: "Send a normal Notify(SOA) to someone",
	Run: func(cmd *cobra.Command, args []string) {
		SendNotify([]string{"soa"})
	},
}

func init() {
	rootCmd.AddCommand(notifyCmd)
	notifyCmd.AddCommand(notifyCdsCmd, notifyCsyncCmd, notifyDnskeyCmd, notifySoaCmd)

	notifyCmd.PersistentFlags().StringVarP(&zonename, "zone", "z", "", "Zone to send a parent notify for")
}

func SendNotify(rrtypes []string) {
	if zonename == "" {
		fmt.Printf("Error: zone name not specified. Terminating.\n")
		os.Exit(1)
	}

	zonename = dns.Fqdn(zonename)
	parentzone := ParentZone(zonename, imr, log.Default())
	var qname string
	var notify_type uint16

	notify_types := map[uint16]bool{}

	for _, rrtype := range rrtypes {
		switch rrtype {
		case "cds":
			qname = fmt.Sprintf("_cds-notifications.%s", parentzone)
			notify_type = dns.TypeCDS
			notify_types[dns.TypeCDS] = true
		case "csync":
			qname = fmt.Sprintf("_csync-notifications.%s", parentzone)
			notify_type = dns.TypeCSYNC
			notify_types[dns.TypeCSYNC] = true
		case "dnskey":
			notify_type = dns.TypeDNSKEY
			fmt.Printf("DNSKEY is a sideways NOTIFY for a Multi-Signer setup. Where do you want to send it?\n")
			os.Exit(0)
		case "soa":
			notify_type = dns.TypeSOA
			fmt.Printf("SOA is a normal NOTIFY. Where do you want to send it?\n")
			os.Exit(0)
		default:
			fmt.Printf("Unknown NOTIFY RRtype: %s. Terminating.\n", rrtype)
			os.Exit(1)
		}
	}
	_ = notify_type

	m := new(dns.Msg)
	m.SetQuestion(qname, dns.TypeSRV)
	res, err := dns.Exchange(m, imr)
	if err != nil {
		log.Fatalf("Error from dns.Exchange(%s, SRV): %v", zonename, err)
	}

	if res.Rcode != dns.RcodeSuccess {
		log.Fatalf("Error: Query for %s SRV received rcode: %s",
			qname, dns.RcodeToString[res.Rcode])
	}

	if len(res.Answer) > 0 {
		rr := res.Answer[0]
		if srv, ok := rr.(*dns.SRV); ok {
			if debug {
				fmt.Printf("Looking up parent notification address:\n%s\n", rr.String())
			}

			msg := fmt.Sprintf("Sending %s Notification for zone %s to: %s:%d",
				strings.ToUpper(rrtypes[0]), zonename, srv.Target, srv.Port)

			m = new(dns.Msg)
			m.SetNotify(zonename)

			m.Question = []dns.Question{} // remove SOA
			for rrtype, _ := range notify_types {
				m.Question = append(m.Question, dns.Question{zonename, rrtype, dns.ClassINET})
			}

			fmt.Printf("Sending Notify:\n%s\n", m.String())

			res, err = dns.Exchange(m, fmt.Sprintf("%s:%d", srv.Target, srv.Port))
			if err != nil {
				log.Fatalf("Error from dns.Exchange(%s, SRV): %v", zonename, err)
			}

			if res.Rcode != dns.RcodeSuccess {
				fmt.Printf(msg+"... and got rcode %s back (bad)\n", dns.RcodeToString[res.Rcode])
				log.Fatalf("Error: Rcode: %s", dns.RcodeToString[res.Rcode])
			} else {
				fmt.Printf(msg + "... and got rcode NOERROR back (good)\n")
			}
		} else {
			log.Fatalf("Error: answer is not an SRV RR: %s", rr.String())
		}
	}
}

func ParentZone(z, imr string, lg *log.Logger) string {
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

		if imr[len(imr)-3:] != ":53" {
			imr = net.JoinHostPort(imr, "53")
		}
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

			lg.Printf("ParentZone: ERROR: Failed to locate parent of '%s' via Answer and Authority. Now guessing.", z)
			return upone
		}
	}
	lg.Printf("ParentZone: had difficulties splitting zone '%s'\n", z)
	return z
}

