# see Makefile for usage

FROM debian:buster

# include the debian non-free repository, for xml2rfc
RUN sed -i -e's/ main/ main non-free/g' /etc/apt/sources.list && apt-get -q update

# install the tools we need
RUN apt-get install -qy make ruby-kramdown-rfc2629 xml2rfc

WORKDIR /rfc
