#!/bin/bash

# test bind
docker restart ruc-bind
docker exec ruc-attacker python3 /root/poc_scripts/basic_test.py --resolver_ip 172.22.1.1

# test powerdns
docker restart ruc-powerdns
docker exec ruc-attacker python3 /root/poc_scripts/basic_test.py --resolver_ip 172.22.1.2

# test unbound
docker restart ruc-unbound
docker exec ruc-attacker python3 /root/poc_scripts/basic_test.py --resolver_ip 172.22.1.3

# test knot
docker restart ruc-knot
docker exec ruc-attacker python3 /root/poc_scripts/basic_test.py --resolver_ip 172.22.1.4

# test technitium
docker restart ruc-technitium
docker exec ruc-attacker python3 /root/poc_scripts/basic_test.py --resolver_ip 172.22.1.5