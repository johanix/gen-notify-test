/*
 * Johan Stenstam, johani@johani.org
 */

package main

import (
	// "crypto"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"

	lib "github.com/johanix/gen-notify-test/lib"
)

type UpdatePolicy struct {
     Type	  string // only "selfsub" known at the moment
     RRtypes	  map[uint16]bool
}

func DnsEngine(scannerq chan ScanRequest, updateq chan UpdateRequest) error {
	addresses := viper.GetStringSlice("dnsengine.addresses")

	verbose := viper.GetBool("dnsengine.verbose")
	debug := viper.GetBool("dnsengine.debug")
	dns.HandleFunc(".", createHandler(scannerq, updateq, verbose, debug))

	log.Printf("DnsEngine: addresses: %v", addresses)
	for _, addr := range addresses {
		for _, net := range []string{"udp", "tcp"} {
			go func(addr, net string) {
				log.Printf("DnsEngine: serving on %s (%s)\n", addr, net)
				server := &dns.Server{Addr: addr, Net: net}

				// Must bump the buffer size of incoming UDP msgs, as updates
				// may be much larger then queries
				server.UDPSize = dns.DefaultMsgSize // 4096
				if err := server.ListenAndServe(); err != nil {
					log.Printf("Failed to setup the %s server: %s\n", net, err.Error())
				} else {
					log.Printf("DnsEngine: listening on %s/%s\n", addr, net)
				}
			}(addr, net)
		}
	}
	return nil
}

func createHandler(scannerq chan ScanRequest, updateq chan UpdateRequest, verbose, debug bool) func(w dns.ResponseWriter, r *dns.Msg) {

	keydir := viper.GetString("ddns.keydirectory")
	keymap, err := lib.ReadPubKeys(keydir)
	if err != nil {
		log.Fatalf("Error from ReadPublicKeys(%s): %v", keydir, err)
	}

	policy := UpdatePolicy{
			Type:		viper.GetString("ddns.policy.type"),
			RRtypes:	map[uint16]bool{},
		  }

	switch policy.Type {
	case "selfsub", "self":
	     // all ok, we know these
	default:
	   log.Fatalf("Error: unknown update policy type: \"%s\". Terminating.", policy.Type)
	}
		  
	var rrtypes []string
	for _, rrstr := range viper.GetStringSlice("ddns.policy.rrtypes") {
	    if rrt, ok := dns.StringToType[rrstr]; ok {
	       policy.RRtypes[rrt] = true
	       rrtypes = append(rrtypes, rrstr)
	    } else {
	      log.Printf("Unknown RR type: \"%s\". Ignoring.", rrstr)
	    }
	}

	if len(policy.RRtypes) == 0 {
	   log.Fatalf("Error: zero valid RRtypes listed in policy.")
	}
	log.Printf("DnsEngine: using update policy \"%s\" with RRtypes: %v", policy.Type, rrtypes)

	return func(w dns.ResponseWriter, r *dns.Msg) {
		var qtype string

		zone := r.Question[0].Name

		log.Printf("DnsHandler: msg received: %s", r.String())

		switch r.Opcode {
		case dns.OpcodeNotify:
			// send NOERROR response
			m := new(dns.Msg)
			m.SetReply(r)
			w.WriteMsg(m)

			for i := 0; i <= len(r.Question)-1; i++ {
				m := r.Question[i]
				qtype = dns.TypeToString[m.Qtype]
				if verbose {
					log.Printf("DnsEngine: Received NOTIFY(%s) for zone %s", qtype, zone)
				}
				scannerq <- ScanRequest{Cmd: "SCAN", ZoneName: zone, RRtype: qtype}
			}
			return

		case dns.OpcodeUpdate:
			log.Printf("DnsEngine: Received UPDATE for zone '%s' containing %d RRs in the update section", zone, len(r.Ns))

			m := new(dns.Msg)
			m.SetReply(r)

			rcode, signername, err := ValidateUpdate(r, keymap)
			if err != nil {
				log.Printf("Error from ValidateUpdate(): %v", err)
			}

			// send response
			m = m.SetRcode(m, int(rcode))
			w.WriteMsg(m)

			if rcode != dns.RcodeSuccess {
				log.Printf("Error verifying DDNS update. Ignoring contents.")
			}

			ok, err := ApproveUpdate(zone, signername, r, policy, verbose, debug)
			if err != nil {
				log.Printf("Error from ApproveUpdate: %v. Ignoring update.", err)
				return
			}

			if !ok {
			   log.Printf("DnsEngine: ApproveUpdate rejected the update. Ignored.")
			   return
			}
			log.Printf("DnsEngine: Update validated and approved. Queued for zone update.")
			// send into suitable channel for pending updates
			updateq <- UpdateRequest{Cmd: "UPDATE", ZoneName: zone, Actions: r.Ns }
			return

		default:
			log.Printf("Error: unable to handle msgs of type %s",
				dns.OpcodeToString[r.Opcode])
		}
	}
}

func ValidateUpdate(r *dns.Msg, keymap map[string]dns.KEY) (uint8, string, error) {
	var rcode uint8 = dns.RcodeSuccess

	if len(r.Extra) == 0 {
	   return dns.RcodeFormatError, "", nil // there is no signature on the update
	}

	if _, ok := r.Extra[0].(*dns.SIG); !ok {
	   return dns.RcodeFormatError, "", nil // there is no SIG(0) signature on the update
	}

	sig := r.Extra[0].(*dns.SIG)
	log.Printf("* Update is signed by \"%s\".", sig.RRSIG.SignerName)
	msgbuf, err := r.Pack()
	if err != nil {
		log.Printf("= Error from msg.Pack(): %v", err)
		rcode = dns.RcodeFormatError
	}

	keyrr, ok := keymap[sig.RRSIG.SignerName]
	if !ok {
		log.Printf("= Error: key \"%s\" is unknown.", sig.RRSIG.SignerName)
		rcode = dns.RcodeBadKey
	}

	err = sig.Verify(&keyrr, msgbuf)
	if err != nil {
		log.Printf("= Error from sig.Varify(): %v", err)
		rcode = dns.RcodeBadSig
	} else {
		log.Printf("* Update SIG verified correctly")
	}

	if lib.SIGValidityPeriod(sig, time.Now()) {
		log.Printf("* Update SIG is within its validity period")
	} else {
		log.Printf("= Update SIG is NOT within its validity period")
		rcode = dns.RcodeBadTime
	}
	return rcode, sig.RRSIG.SignerName, nil
}

func ApproveUpdate(zone, signername string, r *dns.Msg, policy UpdatePolicy, verbose, debug bool) (bool, error) {
     log.Printf("Analysing update using policy type %s with allowed RR types %v",
     			   policy.Type, policy.RRtypes)

	for i := 0; i <= len(r.Ns)-1; i++ {
		rr := r.Ns[i]

		if !policy.RRtypes[rr.Header().Rrtype] {
		   log.Printf("ApproveUpdate: update rejected (unapproved RR type: %s)",
		   			      dns.TypeToString[rr.Header().Rrtype])
		   return false, nil
		}

		switch policy.Type {
		case "selfsub":
		     if !strings.HasSuffix(rr.Header().Name, signername) {
		     	log.Printf("ApproveUpdate: update rejected (owner name %s outside selfsub %s tree)",
		   			      rr.Header().Name, signername)
		        return false, nil
		     }

		case "self":
		     if rr.Header().Name != signername {
		     	log.Printf("ApproveUpdate: update rejected (owner name %s different from signer name %s in violation of \"self\" policy)",
		   			      rr.Header().Name, signername)
		        return false, nil
		     }
		default:
			log.Printf("ApproveUpdate: unknown policy type: \"%s\"", policy.Type)
		        return false, nil
		}

		if rr.Header().Class == dns.ClassNONE {
			log.Printf("ApproveUpdate: Remove RR: %s", rr.String())
		} else if rr.Header().Class == dns.ClassANY {
			log.Printf("ApproveUpdate: Remove RRset: %s", rr.String())
		} else {
			log.Printf("ApproveUpdate: Add RR: %s", rr.String())
		}
	}
	return true, nil
}
