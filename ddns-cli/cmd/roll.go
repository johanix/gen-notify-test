/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package cmd

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	lib "github.com/johanix/gen-notify-test/lib"
)

var rollCmd = &cobra.Command{
	Use:   "roll",
	Short: "Send a DDNS update to roll the SIG(0) key used to sign updates",
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

		keyrr, cs := LoadSigningKey(keyfile)
		if keyrr != nil {
		   fmt.Printf("keyid=%d\n", keyrr.KeyTag())
		} else {
		   fmt.Printf("No signing key specified.\n")
		}

		newkey, err := GenerateSigningKey(lib.Zonename, dns.AlgorithmToString[keyrr.Algorithm])
		if err != nil {
		   log.Fatalf("Error from GenerateSigningKey: %v", err)
		}
		fmt.Printf("new key: %s\n", newkey.String())

		const update_scheme = 2
		dsynctarget, err := lib.LookupDSYNCTarget(pzone, parpri, dns.StringToType["ANY"], update_scheme)
		if err != nil {
			log.Fatalf("Error from LookupDDNSTarget(%s, %s): %v", pzone, parpri, err)
		}

		adds := []dns.RR{ newkey }
		removes := []dns.RR{ keyrr }

		msg, err := CreateUpdate(pzone, lib.Zonename, adds, removes)
		if err != nil {
			log.Fatalf("Error from CreateUpdate(%v): %v", dsynctarget, err)
		}

		if keyfile != "" {
			fmt.Printf("Signing update.\n")
			msg, err = lib.SignMsgNG(msg, lib.Zonename, cs, keyrr)
			if err != nil {
				log.Fatalf("Error from SignMsgNG(%v): %v", dsynctarget, err)
			}
		} else {
			log.Fatalf("Error: Keyfile not specified, key rollover not possible.\n")
		}

		err = SendUpdate(msg, pzone, dsynctarget)
		if err != nil {
			log.Fatalf("Error from SendUpdate(%v): %v", dsynctarget, err)
		}
		

	},
}

func init() {
	rootCmd.AddCommand(rollCmd)

	rootCmd.PersistentFlags().StringVarP(&lib.Zonename, "zone", "z", "", "Child zone to sync via DDNS")
	rootCmd.PersistentFlags().StringVarP(&pzone, "pzone", "Z", "", "Parent zone to sync via DDNS")
	rootCmd.PersistentFlags().StringVarP(&childpri, "primary", "p", "", "Address:port of child primary namserver")
	rootCmd.PersistentFlags().StringVarP(&parpri, "pprimary", "P", "", "Address:port of parent primary nameserver")
	rootCmd.PersistentFlags().StringVarP(&lib.Global.IMR, "imr", "i", "", "IMR to send the query to")
}

func GenerateSigningKey(owner, alg string) (*dns.KEY, error) {
     keygenprog := viper.GetString("roll.keygenerator")
     if keygenprog == "" {
     	log.Fatalf("Error: key generator program not specified.")
     }

     cmdline := fmt.Sprintf("%s -a %s -T KEY -n ZONE %s", keygenprog, alg, owner)
     fmt.Printf("cmd: %s\n", cmdline)
     cmdsl := strings.Fields(cmdline)
     command := exec.Command(cmdsl[0], cmdsl[1:]...)
     out, err := command.CombinedOutput()
     if err != nil {
     	log.Printf("Error from exec: %v: %v\n", cmdsl, err)
     }

     var keyname string

     for _, l := range strings.Split(string(out), "\n") {
     	 if len(l) != 0 {
	    elems := strings.Fields(l)
	    if strings.HasPrefix(elems[0], "K"+owner) {
	       keyname = elems[0]
	       fmt.Printf("New key is in file %s\n", keyname)
	    }
	 }
     }

     keyrr, _ := LoadSigningKey(keyname + ".key")
     if err != nil {
	   return keyrr, err
     } 

     return keyrr, nil     
}