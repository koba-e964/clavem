OBJECTS=ed25519-public.pem ed448-public.pem rsa-libressl-2.2.7-public.pem \
	rsa-pss-public.pem rsa-public.pem x25519-public.pem x448-public.pem

.PHONY: all verify clean
all: verify

%-public.pem: %-private.pem
	openssl pkey -in $< -pubout -out $@

verify: $(OBJECTS) sha256sum.txt
	sha256sum --check sha256sum.txt

clean:
	$(RM) $(OBJECTS)
