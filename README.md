# OpenPGP Cryptographic Refresh of RFC 4880

This repository holds the text for [draft-ietf-openpgp-crypo-refresh](https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/)

The goal of the document is to revise RFC 4880 with the ability to include more modern cryptographic primitives, and to be able to fully deprecate those primitives known to be problematic.

Work should be done in this repository within the primary source document `crypto-refresh.md`.

## Build Dependencies

To build, you need [kramdown-rfc2629](https://github.com/cabo/kramdown-rfc2629), [xml2rfc](https://pypi.org/project/xml2rfc/), and [GNU Make](https://www.gnu.org/software/make/).

On debian systems, these dependencies can be installed with:

    apt install xml2rfc ruby-kramdown-rfc2629 make

## Building the Draft

To build a new version of the draft, use:

    make

This will produce a local `crypto-refresh.html` and `crypto-refresh.txt` for review.
If both of those resulting files look OK, then one of the editors should submit the generated copy of `crypto-refresh.xml` to [the datatracker](https://datatracker.ietf.org/submit/).

## Other Files in this Repository

In addition to `crypto-refresh.md`, this repository contains two other significant source documents in markdown:

`rfc4880.md` is a markdown-variant of the original RFC 4880.
Running `make rfc4880.txt` should produce a .txt document that is very close to [the original RFC](https://tools.ietf.org/rfc/rfc4880.txt)

`rfc4880bis.md` is the re-flowed source of [rfc4880bis-10](https://datatracker.ietf.org/doc/draft-ietf-openpgp-rfc4880bis/10/), which is the earlier version of the draft that was superseded when the OpenPGP WG was re-established in 2020.
At that time, we started over from RFC 4880, and have been re-importing specific topical changes between `rfc4880` and `rfc4880bis`, building WG consensus and review along the way.

All of the markdown documents in this repository should round-trip cleanly through the `reflow` python script.
These source documents are all flowed the same way, one sentence per line, to make it easier and clearer to see differences with tools that look at differences in text documents.
