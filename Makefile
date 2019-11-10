#!/usr/bin/make -f
#
# Prerequisites: apt install ruby-kramdown-rfc2629 xml2rfc
#

draft = rfc4880bis
OUTPUT = $(draft).txt $(draft).html $(draft).xml

all: $(OUTPUT)

%.xmlv2: %.md
	kramdown-rfc2629 < $< > $@.tmp
	mv $@.tmp $@

# convert to v3:
%.xml: %.xmlv2
	xml2rfc -o $@ --v2v3 $<

%.html: %.xml
	xml2rfc $< --html

%.txt: %.xml
	xml2rfc $< --text

$(draft).txt.diff: $(draft).txt compare canonicalizetxt
	! ./compare > $@.tmp
	mv $@.tmp $@

clean:
	-rm -rf $(OUTPUT) $(draft).xmlv2 $(draft).txt.diff

.PHONY: clean all
.SECONDARY: $(draft).xmlv2
