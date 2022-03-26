OBJECTS=ed25519-public.pem rsa-libressl-2.2.7-public.pem rsa-public.pem

.PHONY: all verify clean
all: verify

%-public.pem: %-private.pem
	openssl pkey -in $< -pubout -out $@

verify: $(OBJECTS) sha256sum.txt
	sha256sum --check sha256sum.txt

clean:
	$(RM) $(OBJECTS)
