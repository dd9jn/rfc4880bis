# see Makefile for usage

FROM debian:bookworm-slim

# include the debian non-free repository, for xml2rfc
RUN sed -i -e's/ main/ main non-free/g' /etc/apt/sources.list && apt -q update

# install the tools we need
RUN DEBIAN_FRONTEND=noninteractive apt install -qy --no-install-recommends make ruby-kramdown-rfc2629 xml2rfc

WORKDIR /rfc
