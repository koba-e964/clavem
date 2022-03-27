OBJECTS=ed25519-public.pem ed448-public.pem rsa-3primes-public.pem rsa-libressl-2.2.7-public.pem \
	rsa-pss-public.pem rsa-public.pem x25519-public.pem x448-public.pem
CHECKS=$(OBJECTS:%-public.pem=%.check)

.PHONY: all verify $(wildcard *.check) clean
all: verify $(CHECKS)

%-public.pem: %-private.pem
	openssl pkey -in $< -pubout -out $@

verify: $(OBJECTS) sha256sum.txt
	sha256sum --check sha256sum.txt

$(CHECKS): %.check: %-private.pem %-public.pem
	cargo run -- $*-private.pem
	cargo run -- $*-public.pem

clean:
	$(RM) $(OBJECTS)
