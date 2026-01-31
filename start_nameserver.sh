#!/bin/bash

# build docker image for victim domain's nameserver
docker build -f dockers/nameserver.Dockerfile -t nameserver:ruc .

# start docker container for victim domain's nameserver
docker run -d --name ruc-nameserver --network ruc-test-net --ip 172.22.2.1 nameserver:ruc

echo "[*] Start a container of victim domains' authoritative nameserver for the RUC test, done."