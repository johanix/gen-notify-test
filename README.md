# generalised-notify-test

Demo code for draft-thomassen-generalised-dns-notify-NN

Here is some simple Go code to play with generalised DNS notifications a la
draft-thomassen-generalised-dns-notify-00.

1. Build the receiver (i.e. the server that will listen for NOTIFY):
   (cd receiver/ ; go build)

2. Check the config in receiver.yaml. It must specify at least a
   address and a port on which to listen, as well as a scanner interval
   (time in seconds between periodic scanner runs).

3. Start the receiver.
   (cd reciever ; ./receiver)

4. Build the sender.
   (cd sender/ ; go build)

5. Publish the notification address in a parent zone that you control:

_cds-notifications.parent.example.	IN	SRV 10 10 5302 notifications.parent.example.
_csync-notifications.parent.example.	IN	SRV 10 10 5302 notifications.parent.example.
notifications.parent.example.		IN	A   127.0.0.1

   Note that the IP address (127.0.0.1) and the port (5302) must be the
   same as specified in receiver.yaml (so that the receiver listens in
   the right place).

6. Test:
   cd sender/
   ./sender notify cds --zone foo.parent.example.

Notes:

1. There is (experimental) support for sending multiple notifications in the
   same message:

	./sender notify cds+csync --zone foo.parent.example

   That works fine in the sender end, but in the receiver end
   it requires a minor (4 lines or so) modification to the Golang
   dns package. Otherwise the reciever will return FORMERR.

2. This code needs to be updated to use a private DNS type for the proposed
   NOTIFY RR type from the -01 version of the draft.
