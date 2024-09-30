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

