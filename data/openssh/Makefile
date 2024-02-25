OBJECTS=id_dsa.pub id_ecdsa.pub id_ed25519.pub id_ed25519_encrypted.pub id_rsa.pub
CHECKS=$(OBJECTS:%.pub=%.check)

.PHONY: all verify $(wildcard *.check) clean
all: verify $(CHECKS)

%.pub: %
	if ! ssh-keygen -y -f $< >$@; then rm $@; exit 1; fi
id_ed25519_encrypted.pub: id_ed25519_encrypted
	if ! ssh-keygen -y -f $< >$@ -P passphrase; then rm $@; exit 1; fi

verify: $(OBJECTS) sha256sum.txt
	sha256sum --check sha256sum.txt

$(CHECKS): %.check: % %.pub
	cargo run -- --display-span --output-format=json $* | tee $*.json
	cargo run -- --display-span --output-format=json $*.pub | tee $*.pub.json

clean:
	$(RM) $(OBJECTS)
