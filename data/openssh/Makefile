OBJECTS=id_dsa.pub id_ecdsa.pub id_ed25519.pub id_rsa.pub

.PHONY: all verify clean
all: verify

%.pub: %
	ssh-keygen -y -f $< >$@ 

verify: $(OBJECTS) sha256sum.txt
	sha256sum --check sha256sum.txt

clean:
	$(RM) $(OBJECTS)
