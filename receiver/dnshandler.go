/*
 * (c) Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
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

	return func(w dns.ResponseWriter, r *dns.Msg) {
		var qtype string

		zone := r.Question[0].Name

		// log.Printf("DnsHandler: msg received: %s", r.String())

		if r.Opcode == dns.OpcodeNotify {
			// log.Printf("Received NOTIFY for zone '%s' containing %d RRs", zone, len(r.Question))
			// send NOERROR response
			m := new(dns.Msg)
			m.SetReply(r)
			w.WriteMsg(m)

			// for i, m := range r.Question {
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
		}
	}
}
