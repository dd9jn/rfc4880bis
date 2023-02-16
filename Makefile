# Render crypto-refresh.md into an I-D
#
# Prerequisites: ruby-kramdown-rfc2629 xml2rfc GNU-Make python
#
# For pdf output, also: weasyprint
# Tested with the Debian versions of the tools

draft = crypto-refresh
OUTPUT = $(draft).txt $(draft).html $(draft).xml

all: $(OUTPUT)

%.xml: %.md $(wildcard test-vectors/*)
	kramdown-rfc2629 --v3 $< > $@.tmp
	mv $@.tmp $@

%.html: %.xml
	xml2rfc --v3 $< --html

%.txt: %.xml
	xml2rfc --v3 $< --text

%.pdf: %.xml
	xml2rfc --v3 $< --pdf

$(draft).txt.diff: $(draft).txt compare canonicalizetxt
	! ./compare > $@.tmp
	mv $@.tmp $@

# for cleaner rfcdiff:
rfc4880.trimmed.txt: rfc4880.txt
	grep -v '^ *OpenPGP Message Format *November 2007$$' < $< > $@.tmp
	mv $@.tmp $@

# builds a docker image that can build the targets in this makefile (except pdf output)
# see kramdown-rfc2629-docker/Dockerfile for documentation, it's only three lines
docker-image:
	docker build -t kramdown-rfc2629-docker kramdown-rfc2629-docker/

# runs "make all" in a docker container that mounts this directory as a volume
# this takes the UID and GID from the current env, so the output files don't belong the root
docker-all:
	docker run --rm -i --user ${UID}:${GID} -v $(PWD):/rfc kramdown-rfc2629-docker:latest make

# drops you in a shell in the container, with this directory mounted where you can run "make" more quickly
# this takes the UID and GID from the current env, so the output files don't belong the root
docker-shell:
	docker run --rm -it --user ${UID}:${GID} -v $(PWD):/rfc kramdown-rfc2629-docker:latest bash

clean:
	-rm -rf $(OUTPUT) *.tmp $(draft).txt.diff $(draft).md.reflowed

check: codespell check-reflow

check-reflow:
	./reflow < $(draft).md > $(draft).md.reflowed
	diff -u $(draft).md $(draft).md.reflowed

codespell:
	codespell crypto-refresh.md

.PHONY: clean all check codespell check-reflow
