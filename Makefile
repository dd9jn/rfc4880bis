#!/usr/bin/make -f

OUTPUTS = draft.txt draft.xml draft.html

all: $(OUTPUTS)

draft.txt: abstract.mkd middle.mkd back.mkd
	pandoc2rfc -T abstract.mkd middle.mkd back.mkd

draft.xml: abstract.mkd middle.mkd back.mkd
	pandoc2rfc -X abstract.mkd middle.mkd back.mkd

draft.html: abstract.mkd middle.mkd back.mkd
	pandoc2rfc -H abstract.mkd middle.mkd back.mkd

clean:
	rm -f $(OUTPUTS)

.PHONY: clean all
