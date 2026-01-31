#!/bin/bash

# build the docker image of RUC attacker
docker build -f dockers/ruc_attacker.Dockerfile -t attacker:ruc .

# start the docker container of RUC attacker
docker run -d --name ruc-attacker --network ruc-test-net --ip 172.22.3.1 -v "$(pwd)/poc_scripts/:/root/poc_scripts/" attacker:ruc

echo "[*] Start a container of RUC attacker for the RUC test, done."