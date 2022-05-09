FROM debian:11
RUN apt-get update
RUN apt-get install -yq \
    less \
    nano \
    wget \
    ethtool \
    python3 \
    python3-pip \
    git \
    sudo \
    curl \
    gpg
RUN pip3 install GitPython semantic-version
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_11/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_11/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
RUN sudo apt update
RUN sudo apt install -yq zeek-lts
RUN ln -s /opt/zeek /zeek
RUN export PATH=/zeek/bin/:$PATH
COPY training-res /zeek/training-res/
