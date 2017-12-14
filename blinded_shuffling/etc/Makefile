SERVICES = blinder thresholder analyzer
PRIVATES = $(SERVICES:=.prv.pem)
PUBLICS = $(SERVICES:=.pub.pem)

all: $(PRIVATES) $(PUBLICS)

%.prv.pem:
	openssl ecparam -name prime256v1 -noout -genkey -out $@

%.pub.pem: %.prv.pem
	openssl ec -in $< -pubout -out $@

$(CERTS):
	openssl ecparam -name prime256v1 -noout -genkey -out $@
	openssl ec -in $@ -pubout -out $(@:.pem=-pub.pem)

clean:
	rm -f $(PRIVATES) $(PUBLICS)

.PHONY: all clean
