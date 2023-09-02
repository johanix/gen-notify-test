/*
 * (c) Johan Stenstam, johani@johani.org
 */

package main

import (
	// "crypto"
	"log"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"

	lib "github.com/johanix/gen-notify-test/lib"
)

func DnsEngine(scannerq chan ScanRequest) error {
	addresses := viper.GetStringSlice("dnsengine.addresses")

	verbose := viper.GetBool("dnsengine.verbose")
	debug := viper.GetBool("dnsengine.debug")
	dns.HandleFunc(".", createHandler(scannerq, verbose, debug))

	log.Printf("DnsEngine: addresses: %v", addresses)
	for _, addr := range addresses {
		for _, net := range []string{"udp", "tcp"} {
			go func(addr, net string) {
				log.Printf("DnsEngine: serving on %s (%s)\n", addr, net)
				server := &dns.Server{Addr: addr, Net: net}
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

func createHandler(scannerq chan ScanRequest, verbose, debug bool) func(w dns.ResponseWriter, r *dns.Msg) {

	// var keyrr *dns.KEY
	// var cs crypto.Signer
	//		var rr dns.RR

	//		keyfile := "Kalpha.dnslab.+008+47989.key"
	//
	//	        if keyfile != "" {
	//		   var ktype string
	//		   var err error
	//		   _, _, rr, ktype, err = lib.ReadKey(keyfile)
	//		   if err != nil {
	//		      log.Fatalf("Error reading key '%s': %v", keyfile, err)
	//		   }
	//
	//		   if ktype != "KEY" {
	//		      log.Fatalf("Key must be a KEY RR")
	//		   }
	//
	//		   keyrr = rr.(*dns.KEY)
	//		}
	keydir := viper.GetString("ddns.keydirectory")
	keymap, err := lib.ReadPubKeys(keydir)
	if err != nil {
		log.Fatalf("Error from ReadPublicKeys(%s): %v", keydir, err)
	}

	return func(w dns.ResponseWriter, r *dns.Msg) {
		var qtype string

		zone := r.Question[0].Name

		log.Printf("DnsHandler: msg received: %s", r.String())

		switch r.Opcode {
		case dns.OpcodeNotify:
			// log.Printf("Received NOTIFY for zone '%s' containing %d RRs", zone, len(r.Question))
			// send NOERROR response
			m := new(dns.Msg)
			m.SetReply(r)
			w.WriteMsg(m)

			for i := 0; i <= len(r.Question)-1; i++ {
				m := r.Question[i]
				qtype = dns.TypeToString[m.Qtype]
				// log.Printf("DnsEngine: Processing Question[%d]: %s %s", i, zone, qtype)
				if verbose {
					log.Printf("DnsEngine: Received NOTIFY(%s) for zone %s", qtype, zone)
				}
				scannerq <- ScanRequest{Cmd: "SCAN", ZoneName: zone, RRtype: qtype}
			}
			return

		case dns.OpcodeUpdate:
			log.Printf("Received UPDATE for zone '%s' containing %d RRs in the update section", zone, len(r.Ns))
			// send NOERROR response
			m := new(dns.Msg)
			m.SetReply(r)
			rcode := dns.RcodeSuccess

			if len(r.Extra) == 1 {
				if sig, ok := r.Extra[0].(*dns.SIG); ok {
					log.Printf("Update is signed by \"%s\".", sig.RRSIG.SignerName)
					msgbuf, err := r.Pack()
					if err != nil {
						log.Printf("Error from msg.Pack(): %v", err)
						rcode = dns.RcodeFormatError
					}

					keyrr, ok := keymap[sig.RRSIG.SignerName]
					if !ok {
						log.Printf("Error: key \"\" is unknown.", sig.RRSIG.SignerName)
						rcode = dns.RcodeBadKey
					}

					err = sig.Verify(&keyrr, msgbuf)
					if err != nil {
						log.Printf("Error from sig.Varify(): %v", err)
						rcode = dns.RcodeBadSig
					} else {
						log.Printf("SIG verified correctly")
					}

					if lib.SIGValidityPeriod(sig, time.Now()) {
						log.Printf("SIG is within its validity period")
					} else {
						log.Printf("SIG is NOT within its validity period")
						rcode = dns.RcodeBadTime
					}
				} else {
					rcode = dns.RcodeFormatError
				}
			} else {
				rcode = dns.RcodeFormatError
			}

			// send response back
			m = m.SetRcode(m, rcode)
			w.WriteMsg(m)

			if rcode != dns.RcodeSuccess {
				log.Printf("Error verifying DDNS update. Ignoring contents.")
			}

			AnalyseUpdate(zone, r, verbose, debug)
			return

		default:
			log.Printf("Error: unable to handle msgs of type %s",
				dns.OpcodeToString[r.Opcode])
		}
	}
}

func AnalyseUpdate(zone string, r *dns.Msg, verbose, debug bool) {
	for i := 0; i <= len(r.Ns)-1; i++ {
		rr := r.Ns[i]

		if rr.Header().Class == dns.ClassNONE {
			log.Printf("AnalyseUpdate: Remove RR[%d]: %s", i, rr.String())
		} else {
			log.Printf("AnalyseUpdate: Add RR[%d]: %s", i, rr.String())
		}
	}
	return
}
