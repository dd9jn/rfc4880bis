#!/usr/bin/make -f

OUTPUTS = draft.txt draft.xml draft.html

all: $(OUTPUTS)

draft.txt: abstract.mkd middle.mkd back.mkd
	tools/pandoc2rfc -T abstract.mkd middle.mkd back.mkd
	sed -i 's/R.  Zimmermann/R. Zimmermann/' draft.txt

draft.xml: abstract.mkd middle.mkd back.mkd
	tools/pandoc2rfc -X abstract.mkd middle.mkd back.mkd

draft.html: abstract.mkd middle.mkd back.mkd
	tools/pandoc2rfc -H abstract.mkd middle.mkd back.mkd

clean:
	rm -f $(OUTPUTS)

.PHONY: clean all
