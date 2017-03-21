# SHELL must be Bash in order for process substitution to work
SHELL := /bin/bash
LUNDY := https://gist.githubusercontent.com/JonLundy
CONVDIR := $(LUNDY)/f25c99ee0770e19dc595/raw
CONV := $(CONVDIR)/6035c1c8938fae85810de6aad1ecf6e2db663e26/conv.py
LETSENCRYPT := /etc/letsencrypt/accounts/acme-v01.api.letsencrypt.org/directory
export
env:
	$@
~/.acme-tiny:
	mkdir $@
conv.py:
	wget $(CONV)
~/.acme-tiny/letsencrypt_private_key.der: $(LETSENCRYPT)/*/private_key.json \
 conv.py | ~/.acme-tiny
	[ "$<" ] && openssl asn1parse -noout -out $@ \
	 -genconf <(python conv.py $<)
%.pem: %.der
	openssl rsa -in $< -inform der > $@
%.pem:
	-$(MAKE) ~/.acme-tiny/letsencrypt_private_key.pem
	if [ -e ~/.acme-tiny/letsencrypt_private_key.pem ]; then \
	 ln -sf ~/.acme-tiny/letsencrypt_private_key.pem $@; \
	else \
         openssl genrsa 4096 > $@; \
	fi
certs: ~/.acme-tiny/account_private_key.pem
clean:
	rm -rf conf.py
user_clean:
	rm -rf ~/.acme-tiny
