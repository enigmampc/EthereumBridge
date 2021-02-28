FROM ubuntu:20.04

RUN apt-get -qq -y update && \
    apt-get -qq -y upgrade && \
    DEBIAN_FRONTEND=noninteractive apt-get -qq -y install \
        wget \
        nano \
        git \
        make \
        curl \
        sudo \
        python3-pip \
        bash-completion && \
    apt-get -y autoclean && \
    apt-get -y autoremove && \
    rm -rf /var/lib/apt-get/lists/*


RUN wget -O secretcli https://github.com/enigmampc/SecretNetwork/releases/download/v1.0.3/secretcli-linux-amd64
RUN chmod +x ./secretcli
RUN cp ./secretcli /usr/bin

RUN apt-get install -y softhsm

WORKDIR EthereumBridge/

COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

COPY src/ src/
COPY config/ config/

COPY deployment/config/softhsm2.conf /etc/softhsm/softhsm2.conf

ENTRYPOINT python3 -m src.bridge