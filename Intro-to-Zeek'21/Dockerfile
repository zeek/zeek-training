FROM zeekurity/zeek-generic-debian:latest
RUN apt-get update
RUN apt-get install -yq \
    less \
    nano \
    wget \
    ethtool \
    python3 \
    python3-pip \
    git
RUN pip3 install GitPython semantic-version
COPY training-res /zeek/training-res/
