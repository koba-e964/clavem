OBJECTS=id_dsa.pub id_ecdsa.pub id_ed25519.pub id_rsa.pub
CHECKS=$(OBJECTS:%.pub=%.check)

.PHONY: all verify $(wildcard *.check) clean
all: verify $(CHECKS)

%.pub: %
	ssh-keygen -y -f $< >$@ 

verify: $(OBJECTS) sha256sum.txt
	sha256sum --check sha256sum.txt

$(CHECKS): %.check: % %.pub
	cargo run -- $*

clean:
	$(RM) $(OBJECTS)
