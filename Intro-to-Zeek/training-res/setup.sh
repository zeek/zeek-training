#! /usr/bin/env bash

export DEBIAN_FRONTEND="noninteractive" TZ="America/Los_Angeles"

apt-get update

apt-get -y install \
        curl \
        ethtool \
        gpg \
        iproute2 \
        less \
        nano \
        net-tools \
        procps \
        python3 \
        python3-pip \
        sudo \
        tcpreplay \
        vim \
        wget

# Convenience symlink for the resources in this directory:
if [ ! -d /training ]; then
    thisdir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    ln -s "$thisdir" /training
fi

# Same for the Zeek installation itself:
if [ -d /usr/local/zeek ] && [ ! -d /zeek ]; then
    ln -s /usr/local/zeek /zeek
fi
