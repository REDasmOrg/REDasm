FROM ubuntu:18.04

MAINTAINER bongartz@klimlive.de

RUN apt update \
; apt install -y \
  qt5-qmake \
  qt5-default \
  qtwebengine5-dev \
  libqt5webenginewidgets5 \
  cmake \
  g++ \
  git

COPY ./nightly-entrypoint.sh /

ENTRYPOINT ["/nightly-entrypoint.sh"]
