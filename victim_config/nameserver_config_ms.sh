#!/bin/bash

# install the docker engine
apt update
apt install -y docker.io

# configure the IP alias for this host
cp netplan.yaml /etc/netplan/50-cloud-init.yaml
netplan apply

# build docker image of the authoritative nameserver
docker build -f dockers/nameserver.Dockerfile --build-arg APEX_ZONE=dnssec-ruc-ms.xyz -t nameserver:ruc-ms ..

# run the container for the authoritative nameserver
docker run -d --name ruc-nameserver -p 192.168.45.70:53:53/udp -p 192.168.45.70:53:53/tcp -p 192.168.45.70:57691:57691/tcp nameserver:ruc-ms

echo "[*] Start a container of victim domains' authoritative nameserver for the RUC test, done."