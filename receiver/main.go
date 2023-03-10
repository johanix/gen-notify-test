/*
 * (c) Copyright Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"github.com/spf13/viper"
)

func mainloop() {
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		for {
			select {
			case <-exit:
				log.Println("mainloop: Exit signal received. Cleaning up.")
				wg.Done()
			}
		}
	}()
	wg.Wait()

	log.Println("mainloop: leaving signal dispatcher")
}

func main() {
	viper.SetConfigFile("receiver.yaml")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Error reading config '%s': %v\n", viper.ConfigFileUsed(), err)
	}

	scannerq := make(chan ScanRequest, 5)
	go ScannerEngine(scannerq)
	go DnsEngine(scannerq)

	mainloop()
}
