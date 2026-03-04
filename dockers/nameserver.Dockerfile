FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

ARG APEX_ZONE
ENV APEX_ZONE=$APEX_ZONE

# install BIND latest version
RUN apt update && \
    apt install -y software-properties-common && \
    add-apt-repository -y ppa:isc/bind && \
    apt update && \
    apt install -y bind9 python3-pip screen

# install python dependencies
RUN pip3 install dnslib flask flask_basicauth

# copy nameserver configuration files
RUN mkdir -p /etc/bind
COPY victim_config/$APEX_ZONE/bind/ /etc/bind/
COPY victim_config/named /etc/init.d/
RUN chmod +x /etc/init.d/named

# copy attacker api scripts
RUN mkdir -p /root/attack_api
COPY victim_config/attack_api/ /root/attack_api/
COPY poc_scripts/config.json /root/attack_api/

# initialize victim domain's nameserver
EXPOSE 53/tcp 53/udp 57691/tcp
WORKDIR /root/attack_api/
RUN chmod +x nameserver_init.sh
ENTRYPOINT ["./nameserver_init.sh"]
