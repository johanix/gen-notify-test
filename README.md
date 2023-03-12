# generalised-notify-test

Demo code for draft-thomassen-generalised-dns-notify-NN

Here is some simple Go code to play with generalised DNS notifications a la
draft-thomassen-generalised-dns-notify-01.

1. Build the receiver (i.e. the server that will listen for NOTIFY):
   (cd receiver/ ; go build)

2. Check the config in receiver.yaml. It must specify at least a
   address and a port on which to listen, as well as a scanner interval
   (time in seconds between periodic scanner runs).

3. Start the receiver. By default it will listen on 127.0.0.1:5302 and
   the only thing it does is to fake a periodic scanning of child
   zones and listen for notifications about specific scan requests.
   
   (cd reciever ; ./receiver)

4. Build the test utility.
   (cd notify ; go build)

5. Generate suitable RFC 3597 records to put in your parent zone:

   #./notify rfc3597 --record "parent.example. NOTIFY CDS 1 5302 notifications.parent.example."
   Normal  : "parent.example.     3600    IN      NOTIFY  CDS     1 5302 notifications.parent.example."
   RFC 3597: "parent.example.     3600    CLASS1  TYPE3994        \# 35 003b0114b60d6e6f74696669636174696f6e73076578616d706c6506706172656e7400"
   #./notify rfc3597 --record "parent.example. NOTIFY CSYNC 1 5302 notifications.parent.example."
   Normal  : "parent.example.     3600    IN      NOTIFY  CSYNC   1 5302 notifications.parent.example."
   RFC 3597: "parent.example.     3600    CLASS1  TYPE3994        \# 35 003e0114b60d6e6f74696669636174696f6e73076578616d706c6506706172656e7400"

6. Publish the RFC 3597 records in the parent zone, plus at least one address record for the
   actual notification address. The simplest alternative is to use 127.0.0.1:

notifications.parent.example.	IN	A	127.0.0.1

   Note that the IP address (127.0.0.1) and the port (5302) must be the
   same as specified in receiver.yaml (so that the receiver listens in
   the right place).

6. Play with the test utility:
   cd notify/

	1. Send queries:
	
	#./notify query --zone axfr.net
    parent.example.   3600    IN  NOTIFY  CDS     1 5302 notifications.parent.example.
    parent.example.   3600    IN  NOTIFY  CSYNC   1 5302 notifications.parent.example.
	
    2. Send a NOTIFY(CDS) for child.parent.example:

	#./notify send cds --zone child.parent.example
	
	(the only visible result is in the receiver end)
	
	3. See more details by using the verbose flag:

	#./notify send cds --zone foo.parent.example -v
	Looked up published notification address for NOTIFY(CDS) to parent zone parent.example.:
	parent.example.       3600    IN      NOTIFY  CDS     1 5302 notifications.parent.example.
	notifications.parent.example. has the IP addresses: [127.0.0.1]
	Sending NOTIFY(CDS) to notifications.parent.example. on address 127.0.0.1:5302
	... and got rcode NOERROR back (good)

Notes:

1. There is (experimental) support for sending multiple notifications in the
   same message:

	./notify send cds+csync --zone foo.parent.example

   That works fine in the sender end, but in the receiver end
   it requires a minor (4 lines or so) modification to the Golang
   dns package. Otherwise the reciever will return FORMERR.

2. This code needs to be updated to use a private DNS type for the proposed
   NOTIFY RR type from the -01 version of the draft.
