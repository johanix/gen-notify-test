all:
	$(MAKE) -C receiver
	$(MAKE) -C notify
	$(MAKE) -C ddns-cli
