module ddns-cli

go 1.19

replace github.com/johanix/gen-notify-test/lib => ../lib

require (
	github.com/johanix/gen-notify-test/lib v0.0.0-00010101000000-000000000000
	github.com/miekg/dns v1.1.55
	github.com/spf13/cobra v1.6.1
)

require (
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/mod v0.7.0 // indirect
	golang.org/x/net v0.4.0 // indirect
	golang.org/x/sys v0.3.0 // indirect
	golang.org/x/tools v0.3.0 // indirect
)
