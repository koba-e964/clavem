OBJECTS=ed25519-public.pem ed448-public.pem rsa-3primes-public.pem rsa-libressl-2.2.7-public.pem \
	rsa-pss-public.pem rsa-public.pem x25519-public.pem x448-public.pem
CSRS=ed25519.csr ed448.csr rsa-3primes.csr rsa-libressl-2.2.7.csr \
	rsa-pss.csr rsa.csr
CHECKS=$(OBJECTS:%-public.pem=%.check)
CHECKS_CSR=$(CSRS:%.csr=%.check_csr)

.PHONY: all verify $(wildcard *.check) $(wildcard *.check_csr) clean
all: verify $(CHECKS) $(CHECKS_CSR)

%-public.pem: %-private.pem
	openssl pkey -in $< -pubout -out $@

%.csr: %-private.pem
	openssl req -new -key $< -out $@ -config req.conf

verify: $(OBJECTS) sha256sum.txt
	sha256sum --check sha256sum.txt

$(CHECKS): %.check: %-private.pem %-public.pem
	cargo run -- $*-private.pem
	cargo run -- $*-public.pem

$(CHECKS_CSR): %.check_csr: %.csr
	cargo run -- $*.csr

clean:
	$(RM) $(OBJECTS)
