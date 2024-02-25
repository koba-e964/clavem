SHELL = /bin/bash -o pipefail

OBJECTS=id_dsa.pub id_ecdsa.pub id_ed25519.pub id_ed25519_encrypted.pub id_rsa.pub
CERTS=$(CSRS:%.pub:%-cert.pub)
CHECKS=$(OBJECTS:%.pub=%.check)
CHECKS_CERT=$(OBJECTS:%.pub=%.check_cert)

.PHONY: all verify $(wildcard *.check) clean
all: verify $(CHECKS) $(CHECKS_CERT)

%.pub: %
	if ! ssh-keygen -y -f $< >$@; then rm $@; exit 1; fi
id_ed25519_encrypted.pub: id_ed25519_encrypted
	if ! ssh-keygen -y -f $< >$@ -P passphrase; then rm $@; exit 1; fi

%-cert.pub: %.pub id_ed25519
	@# 2024-02-25 12:00:00 UTC to 2024-02-26 12:00:00 UTC
	ssh-keygen -s id_ed25519 -I test-certificate -n koba,kobae964 -V 20240225120000UTC:20240226120000UTC $*.pub

verify: $(OBJECTS) $(CERTS) sha256sum.txt
	sha256sum --check sha256sum.txt

$(CHECKS): %.check: % %.pub
	set -o pipefail
	cargo run -- --display-span --output-format=json $* | tee $*.json
	cargo run -- --display-span --output-format=json $*.pub | tee $*.pub.json

$(CHECKS_CERT): %.check_cert: %-cert.pub
	set -o pipefail
	cargo run -- --display-span --output-format=json $*-cert.pub | tee $*-cert.pub.json

clean:
	$(RM) $(OBJECTS)
