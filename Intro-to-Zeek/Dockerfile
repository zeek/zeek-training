FROM zeek/zeek
RUN apt-get update
RUN apt-get install -yq \
    less \
    vim \
    nano \
    wget \
    ethtool \
    python3 \
    python3-pip \
    git \
    sudo \
    curl \
    iproute2 \
    net-tools \
    procps \
    gpg
RUN sudo rm /usr/lib/python3.*/EXTERNALLY-MANAGED
RUN pip3 install --break-system-packages GitPython semantic-version
RUN sudo apt update
RUN ln -s /usr/local/zeek /zeek
ENV PATH=/zeek/bin/:$PATH
COPY training-res /zeek/training-res/
