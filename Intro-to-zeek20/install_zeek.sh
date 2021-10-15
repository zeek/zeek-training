#!/bin/bash

echo "Updating the system first.."

apt-get update

echo "System Update complete."

echo "======================="

echo "Upgrading the system.."

apt-get upgrade

echo "System Upgrage complete."

echo "======================="

echo "Installing dependencies.."

apt install -y curl

apt-get install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev

echo "Installing dependencies complete."

echo "======================="

echo "Installing Zeek-LTS.."

echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_18.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list

curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_18.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security:zeek.gpg > /dev/null

apt-get update

apt-get install -y zeek-lts

echo "Installing Zeek-LTS complete."

echo "======================="

echo "Now Add the Zeek binary to your path by running following command:"
echo "export PATH=/opt/zeek/bin/:$PATH"
