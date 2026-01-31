#!/bin/bash

# build docker images
docker build -f dockers/resolver_software/bind.Dockerfile -t ruc-bind:9.20.3 .
docker build -f dockers/resolver_software/powerdns.Dockerfile -t ruc-powerdns:5.1.3 .
docker build -f dockers/resolver_software/unbound.Dockerfile -t ruc-unbound:1.22.0 .
docker build -f dockers/resolver_software/knot.Dockerfile -t ruc-knot:5.7.4 .
docker build -f dockers/resolver_software/technitium.Dockerfile -t ruc-technitium:13.1 .

# start docker containers
docker run -d --name ruc-bind --network ruc-test-net --ip 172.22.1.1 ruc-bind:9.20.3
docker run -d --name ruc-powerdns --network ruc-test-net --ip 172.22.1.2 ruc-powerdns:5.1.3
docker run -d --name ruc-unbound --network ruc-test-net --ip 172.22.1.3 ruc-unbound:1.22.0
docker run -d --name ruc-knot --network ruc-test-net --ip 172.22.1.4 ruc-knot:5.7.4
docker run -d --name ruc-technitium --network ruc-test-net --ip 172.22.1.5 ruc-technitium:13.1

echo "[*] Start containers of tested DNS resolvers for the RUC test, done."