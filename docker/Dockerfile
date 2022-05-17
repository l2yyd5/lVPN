FROM ubuntu:jammy

RUN apt-get update  \
    && apt-get -y install  \
          openbsd-inetd \
          iputils-ping  \
          iproute2      \
          net-tools     \
          dnsutils      \
          mtr-tiny      \
          nano          \
          vim           \
          vsftpd        \
          telnetd       \
          telnet        \
          tcpdump       \
    && apt-get clean

RUN sed -i 's/anonymous_enable=.*/anonymous_enable=YES/g' /etc/vsftpd.conf
RUN echo test > /srv/ftp/testfile

RUN echo 'root:seed' | chpasswd
RUN useradd seedubuntu
RUN echo 'seedubuntu:seed' | chpasswd

COPY ./clientConf.json /task3/
COPY ./certs /task3/certs
COPY ./lVPNclient /task3/
