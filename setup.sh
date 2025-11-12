#!/bin/bash

print_colored_ascii() {
    local ascii_input="$1"
    local WHITE='\033[1;37m'
    local BLUE='\033[0;34m'
    local RESET='\033[0m'

    while IFS= read -r line; do
        output=""
        for ((i=0; i<${#line}; i++)); do
            char="${line:$i:1}"
            case "$char" in
                "@") output+="${WHITE}${char}${RESET}" ;;
                "%"|"#"|"+") output+="${BLUE}${char}${RESET}" ;;
                *) output+="$char" ;;
            esac
        done
        printf "%b\n" "$output"
    done <<< "$ascii_input"
}

LOGO='
         @
        @@
      @@ @
    @@   @
  @@     @@@@@@@@@@@@@@@@@@@@@@
 @@                          @@
  @@     @@##########       @
    @@   @@##########
      @@ @       ###
        @@      ###     @
         @     ###      @@
           ###        @ @@
           ##########@@   @@
     @     ##########@@     @@
   @@                         @@
  @@@@@@@@@@@@@@@@@@@@@     @@
                      @   @@
                      @ @@
                      @@
                      @
'

ALL_TARGETS=("tutorial" "intro-to-zeek", "print")

setup_tutorial() {
  echo "Cloning Zeek source code"
  # TODO: This should change to the first release with the changes.
  git clone -b topic/etyp/doc-tutorial https://github.com/zeek/zeek.git
  echo
  echo
  echo "Cloning example CVE detection source code"
  git clone https://github.com/corelight/cve-2022-26809
  ln -sfn $(pwd)/zeek/testing/btest/Traces/ $(pwd)/traces/zeek-testing
  ln -sfn $(pwd)/zeek/doc/traces/ $(pwd)/traces/zeek-doc
  ln -sfn $(pwd)/zeek/doc/tutorial/scripting/scripts/ $(pwd)/scripts/basics
  ln -sfn $(pwd)/zeek/doc/tutorial/scripting/tutorial/ $(pwd)/scripts/tutorial
}

setup_intro_to_zeek() {
  ln -sfn $(pwd)/Intro-to-Zeek/training-res/traces $(pwd)/traces/Intro-to-Zeek
  ln -sfn $(pwd)/Intro-to-Zeek/training-res/scripts $(pwd)/scripts/Intro-to-Zeek
  ln -sfn $(pwd)/Intro-to-Zeek/training-res/misc $(pwd)/misc/Intro-to-Zeek
}

usage() {
  echo "Usage: $0 [tutorial|intro-to-zeek|all]"
}

# If no arguments, show usage
if [ $# -eq 0 ]; then
  usage
  exit 0
fi

SELECTED=()
for arg in "$@"; do
  if [[ "$arg" == "all" ]]; then
    SELECTED=("${ALL_TARGETS[@]}")
    break
  else
    SELECTED+=("$arg")
  fi
done

# This prints the logo and exits if 'print' is an argument.
if [[ "${#SELECTED[@]}" -eq 1 && "${SELECTED[0]}" == "print" ]]; then
    print_colored_ascii "$LOGO"
    exit 0
fi

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
echo
echo "Installing useful programs"

# Avoid the Wireshark prompt
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -qq -y --no-install-recommends \
    curl \
    ethtool \
    gpg \
    iproute2 \
    iputils-ping \
    less \
    libpcap-dev \
    nano \
    net-tools \
    procps \
    psmisc \
    python3 \
    python3-pip \
    sudo \
    tcpdump \
    tcpreplay \
    tshark \
    vim \
    wget \
    wireshark

echo
echo
mkdir traces/
mkdir scripts/
mkdir misc/

for item in "${SELECTED[@]}"; do
  case "$item" in
    tutorial)
      setup_tutorial
      ;;
    intro-to-zeek)
      setup_intro_to_zeek
      ;;
    *)
      echo "Unknown setup target: $item"
      usage
      ;;
  esac
done

echo
echo
echo 'export PS1="\[\033[1;32m\]\u@zeek-tutorial\[\033[0;34m\]:\w\[\033[0m\] \\$ "' >> /etc/bash.bashrc
echo 'export PREFIX=/usr/local/zeek' >> /etc/bash.bashrc

# ANSI escape codes
WHITE='\033[37m'
BLUE='\033[34m'
RESET='\033[0m'

echo
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
