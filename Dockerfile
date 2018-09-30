FROM ubuntu:16.04

RUN apt-get update && \
    apt-get --no-install-recommends --yes install \
         git \
         automake \
         build-essential \
         libtool \
         cmake \
         autotools-dev \
         autoconf \
         pkg-config \
         libssl-dev \ 
         libboost-all-dev \
         libevent-dev \
         bsdmainutils \
         vim \
         software-properties-common

RUN add-apt-repository ppa:bitcoin/bitcoin && \
    apt-get update && \
    apt-get --no-install-recommends --yes install \
          libdb4.8-dev \
          libdb4.8++-dev \
          libminiupnpc-dev 

WORKDIR /pluracoin

ENV PLURACOIN_VERSION 1.5.0 

RUN git clone https://github.com/pluracoin/PluraCoin.git . && \
    git checkout $PLURACOIN_VERSION && \
    make

VOLUME ["/root/.pluracoin"]

EXPOSE 19200

ENTRYPOINT ["/pluracoin/build/release/src/./pluracoind"]
