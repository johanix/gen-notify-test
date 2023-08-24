/*
*/
package cmd

import (
        "crypto"
	"crypto/rsa"
	"fmt"
	// "io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var filename string

// type MySigner struct {
//      privkey  crypto.PrivateKey
//      KeyRR    dns.KEY
// }
// 
// func (s MySigner) Sign(r io.Reader, data []byte, opts crypto.SignerOpts) ([]byte, error) {
//      var sig []byte
//      fmt.Printf("MySigner.Sign() called\n")
//      // return s.privkey.Sign(r, data), nil
//      return sig, nil
// }
// 
// func (s MySigner) Public() crypto.PublicKey {
//      fmt.Printf("MySigner.Public() called\n")
//      return s.KeyRR.DNSKEY.PublicKey
// }

var readkeyCmd = &cobra.Command{
	Use:   "readkey",
	Short: "read a DNS key, either a KEY or DNSKEY. arg is either the .key or the .private file",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("readkey called")

		k, cs, rr, ktype, err := ReadKey()
		if err != nil {
		   log.Fatalf("Error reading key '%s': %v",
		   		     filename, err)
		}
		
		fmt.Printf("PubKey: %s\n", rr.String())
		fmt.Printf("PrivKey (%s): %v\n", ktype, k)
		fmt.Printf("crypto.Signer: %v\n", cs)
	},
}

var signMsgCmd = &cobra.Command{
	Use:   "signmsg",
	Short: "sign a dns Msg using a private key",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("signmsg called")

		_, cs, rr, ktype, err := ReadKey()
		if err != nil {
		   log.Fatalf("Error reading key '%s': %v", filename, err)
		}
		
		if ktype != "KEY" {
		   log.Fatalf("Key must be a KEY RR")
		}

		keyrr := rr.(*dns.KEY)

		m := new(dns.Msg)
		m.SetUpdate("dnslab.")
		addstr := "alpha.dnslab. 60 IN NS ns.alpha.dnslab."
		adds, err := dns.NewRR(addstr)
		if err != nil {
		   log.Fatalf("Error parsing rr to add '%s': %v", addstr, err)
		}
		m.Insert([]dns.RR{ adds })
		sigrr := new(dns.SIG)
		sigrr.Hdr = dns.RR_Header{
				Name:	keyrr.Header().Name,
				Rrtype:	dns.TypeSIG,
				Class:	dns.ClassINET,
				Ttl:	300,
			    }
		sigrr.RRSIG.KeyTag = keyrr.DNSKEY.KeyTag()
		sigrr.RRSIG.Algorithm = keyrr.DNSKEY.Algorithm
		incep := uint32(time.Now().UTC().Unix())
		expir := incep + 300
		sigrr.RRSIG.Inception = incep
		sigrr.RRSIG.Expiration = expir
		
		fmt.Printf("sigrr: %v\n", sigrr.String())
		
//		mys := MySigner{
//				privkey:	k,
//				KeyRR:		*keyrr,
//		       }
		
		res, err := sigrr.Sign(cs, m)
		if err != nil {
		   log.Fatalf("Error from sig.Sign: %v", err)
		}
		fmt.Printf("%s\n", string(res))
		// fmt.Printf("k: %v\n", k)
		fmt.Printf("Signed msg: %s\n", m.String())
		fmt.Printf("Completed SIG RR: %s\n", sigrr.String())
	},
}

func init() {
	rootCmd.AddCommand(readkeyCmd, signMsgCmd)
	readkeyCmd.Flags().StringVarP(&filename, "keyfile", "f", "", "Name of private key file")
	signMsgCmd.Flags().StringVarP(&filename, "keyfile", "f", "", "Name of private key file")
}

func ReadKey() (crypto.PrivateKey, crypto.Signer, dns.RR, string, error) {

		if filename == "" {
		   log.Fatalf("Error: filename of key not specified")
		}

		var basename, pubfile, privfile string

		if strings.HasSuffix(filename, ".key") {
		   basename = strings.TrimSuffix(filename, ".key")
		   pubfile = filename
		   privfile = basename + ".private"
		} else if strings.HasSuffix(filename, ".private") {
		   basename = strings.TrimSuffix(filename, ".private")
		   privfile = filename
		   pubfile = basename + ".key"
		} else {
		   log.Fatalf("Error: filename %s does not end in either .key or .private", filename)
		}

		file, err := os.Open(pubfile)
		if err != nil {
		   log.Fatalf("Error opening public key file '%s': %v",
		   		     pubfile, err)
		}
		pubkeybytes, err := os.ReadFile(pubfile)
		if err != nil {
		   log.Fatalf("Error reading public key file '%s': %v",
		   		     pubfile, err)
		}
		pubkey := string(pubkeybytes)

		file, err = os.Open(privfile)
		if err != nil {
		   log.Fatalf("Error opening private key file '%s': %v",
		   		     privfile, err)
		}

		rr, err := dns.NewRR(pubkey)
		if err != nil {
		   log.Fatalf("Error reading public key '%s': %v",
		   		     pubkey, err)
		}

		var k crypto.PrivateKey
		var cs crypto.Signer
		var ktype string
		var alg uint8

		// fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rr.Algorithm])

		switch rr.(type) {
		case *dns.DNSKEY:
		     rrk := rr.(*dns.DNSKEY)
		     k, err = rrk.ReadPrivateKey(file, "/allan/tar/kakan")
		     if err != nil {
		     	log.Fatalf("Error reading private key file '%s': %v", filename, err)
		     }
		     ktype = "DNSKEY"
		     alg = rrk.Algorithm
		     fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rrk.Algorithm])
		case *dns.KEY:
		     rrk := rr.(*dns.KEY)
		     k, err = rrk.ReadPrivateKey(file, "/allan/tar/kakan")
		     ktype = "KEY"
		     alg = rrk.Algorithm
		     fmt.Printf("PubKey is a %s\n", dns.AlgorithmToString[rrk.Algorithm])
		default:
			log.Fatalf("Error: rr is of type %v", "foo")
		}
		
		switch alg {
		case dns.RSASHA256:
		     cs = k.(*rsa.PrivateKey)
		default:
		     log.Fatalf("Error: no support for algorithm %s yet", dns.AlgorithmToString[alg])
		}

		return k, cs, rr, ktype, nil
}