#!/bin/bash

echo "Let's Install zkg Zeek package manager.."
echo "========================"

echo "Install pip, git"

apt install -y python-pip
apt-get install -y git

export PATH=/opt/zeek/bin/:$PATH

echo "Installing zkg.."
pip install zkg

echo "zkg install complete."

echo "Auto-configure zkg settings"
zkg autoconfig
