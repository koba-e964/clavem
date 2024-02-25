OBJECTS=ed25519-public.pem ed448-public.pem rsa-3primes-public.pem rsa-libressl-2.2.7-public.pem \
	rsa-pss-public.pem rsa-public.pem x25519-public.pem x448-public.pem
CSRS=ed25519.csr ed448.csr rsa-3primes.csr rsa-libressl-2.2.7.csr \
	rsa-pss.csr rsa.csr
CERTS=$(CSRS:%.csr:%.crt)
CHECKS=$(OBJECTS:%-public.pem=%.check)
CHECKS_CSR=$(CSRS:%.csr=%.check_csr)

.PHONY: all verify $(wildcard *.check) $(wildcard *.check_csr) clean
all: verify $(CHECKS) $(CHECKS_CSR)

%-public.pem: %-private.pem
	openssl pkey -in $< -pubout -out $@

%.csr: %-private.pem
	openssl req -new -key $< -out $@ -config req.conf

%.crt: %.csr
	openssl req -in $< -key ed25519-private.pem -x509 -out $@

verify: $(OBJECTS) sha256sum.txt
	sha256sum --check sha256sum.txt

$(CHECKS): %.check: %-private.pem %-public.pem
	cargo run -- --display-span --output-format=json $*-private.pem | tee $*-private.json
	cargo run -- --display-span --output-format=json $*-public.pem | tee $*-public.json

$(CHECKS_CSR): %.check_csr: %.csr %.crt
	cargo run -- --display-span --output-format=json $*.csr | tee $*.csr.json
	cargo run -- --display-span --output-format=json $*.crt | tee $*.crt.json

clean:
	$(RM) $(OBJECTS)
