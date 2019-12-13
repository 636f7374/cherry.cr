FROM crystallang/crystal:latest

RUN apt-get -y update
RUN apt-get -y upgrade
RUN apt-get install openssl -y
RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir -p /root/.cache/crystal
