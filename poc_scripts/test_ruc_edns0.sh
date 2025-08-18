#!/bin/bash

# test bind
echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Tesing BIND resolver against ruc_edns0..."
docker restart ruc-bind
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.1 --ruc_variant ruc_edns0

# test powerdns
echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Tesing PowerDNS resolver against ruc_edns0..."
docker restart ruc-powerdns
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.2 --ruc_variant ruc_edns0

# test unbound
echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Tesing Unbound resolver against ruc_edns0..."
docker restart ruc-unbound
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.3 --ruc_variant ruc_edns0

# test knot
echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Tesing Knot resolver against ruc_edns0..."
docker restart ruc-knot
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.4 --ruc_variant ruc_edns0

# test technitium
echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Tesing Technitium resolver against ruc_edns0..."
docker restart ruc-technitium
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.5 --ruc_variant ruc_edns0
