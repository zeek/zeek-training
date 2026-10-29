#!/bin/bash

ALL_TARGETS=("tutorial" "intro-to-zeek")

setup_tutorial() {
  echo "Cloning Zeek source code"
  # TODO: This should change to the first release with the changes.
  git clone https://github.com/zeek/zeek.git
  echo
  echo
  echo "Cloning example RCE detection source code"
  git clone https://github.com/zeek/redis-rce

  mkdir -p traces scripts misc

  ln -sfn $(pwd)/zeek/testing/btest/Traces/ $(pwd)/traces/zeek-testing
  ln -sfn $(pwd)/zeek/doc/traces/ $(pwd)/traces/zeek-doc
  ln -sfn $(pwd)/zeek/doc/tutorial/scripting/scripts/ $(pwd)/scripts/basics
  ln -sfn $(pwd)/zeek/doc/tutorial/scripting/tutorial/ $(pwd)/scripts/tutorial
}

usage() {
  echo "Usage: $0 [tutorial|intro-to-zeek]"
}

# If no arguments, show usage
if [ $# -eq 0 ]; then
  usage
  exit 0
fi

SELECTED=()
for arg in "$@"; do
  SELECTED+=("$arg")
done

# Validate all entries before doing any setup
for item in "${SELECTED[@]}"; do
  FOUND=0
  for valid in "${ALL_TARGETS[@]}"; do
    if [[ "$item" == "$valid" ]]; then
      FOUND=1
      break
    fi
  done
  if [[ $FOUND -eq 0 ]]; then
    echo "Unknown setup target: $item"
    usage
    exit 1
  fi
done

# Everything below happens regardless of the input
echo
echo "Installing useful programs"

# Avoid the Wireshark prompt
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -qq -y --no-install-recommends \
    bash-completion \
    curl \
    ethtool \
    iproute2 \
    iputils-ping \
    less \
    nano \
    net-tools \
    procps \
    psmisc \
    sudo \
    tcpdump \
    tcpreplay \
    tmux \
    tshark \
    vim \
    wget

# A more useful prompt
echo 'export PS1="\[\033[1;32m\]\u@zeek-tutorial\[\033[0;34m\]:\w\[\033[0m\] \\$ "' >> /etc/bash.bashrc
echo 'export PREFIX=/usr/local/zeek' >> /etc/bash.bashrc

for item in "${SELECTED[@]}"; do
  case "$item" in
    tutorial)
      setup_tutorial
      ;;
    intro-to-zeek)
      # Nothing for now
      ;;
    *)
      echo "Unknown setup target: $item"
      usage
      ;;
  esac
done

echo
echo "Welcome to the Zeek training/tutorial!"
echo
echo "The script you just ran installed some useful programs."
echo "It also linked some directories for packet captures (pcaps),"
echo "scripts, and more."
echo
echo "To exit the container, simply use the 'exit' command twice."
echo
echo "Feel free to browse the scripts and traces directories."
echo "This is a standard Ubuntu docker image - install what you need!"

# exec bash so that we get the prompt update
exec bash
