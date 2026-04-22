#!/bin/bash

# test bind
python3 renew_resolver.py --resolver bind
bash warm_cache.sh 172.22.1.1
docker exec ruc-attacker python3 /root/poc_scripts/basic_test.py --resolver_ip 172.22.1.1

# test powerdns
python3 renew_resolver.py --resolver powerdns
docker exec ruc-attacker python3 /root/poc_scripts/basic_test.py --resolver_ip 172.22.1.2

# test unbound
python3 renew_resolver.py --resolver unbound
docker exec ruc-attacker python3 /root/poc_scripts/basic_test.py --resolver_ip 172.22.1.3

# test knot
python3 renew_resolver.py --resolver knot
docker exec ruc-attacker python3 /root/poc_scripts/basic_test.py --resolver_ip 172.22.1.4

# test technitium
python3 renew_resolver.py --resolver technitium
docker exec ruc-attacker python3 /root/poc_scripts/basic_test.py --resolver_ip 172.22.1.5