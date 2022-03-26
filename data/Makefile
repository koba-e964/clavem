.PHONY: all openssh pem clean
all: pem openssh

openssh:
	$(MAKE) -C openssh/

pem:
	$(MAKE) -C pem/

clean:
	$(MAKE) -C pem/ clean
	$(MAKE) -C openssh/ clean
