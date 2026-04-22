#!/bin/bash

# test bind
echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Testing BIND resolver against ruc_dnskey (w/o SIG)..."
python3 renew_resolver.py --resolver bind
bash warm_cache.sh 172.22.1.1
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.1 --ruc_variant ruc_dnskey --with_sig 0

echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Testing BIND resolver against ruc_dnskey (w/ SIG)..."
python3 renew_resolver.py --resolver bind
bash warm_cache.sh 172.22.1.1
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.1 --ruc_variant ruc_dnskey --with_sig 1

# test powerdns
echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Testing PowerDNS resolver against ruc_dnskey (w/o SIG)..."
python3 renew_resolver.py --resolver powerdns
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.2 --ruc_variant ruc_dnskey --with_sig 0

echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Testing PowerDNS resolver against ruc_dnskey (w/ SIG)..."
python3 renew_resolver.py --resolver powerdns
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.2 --ruc_variant ruc_dnskey --with_sig 1

# test unbound
echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Testing Unbound resolver against ruc_dnskey (w/o SIG)..."
python3 renew_resolver.py --resolver unbound
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.3 --ruc_variant ruc_dnskey --with_sig 0

echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Testing Unbound resolver against ruc_dnskey (w/ SIG)..."
python3 renew_resolver.py --resolver unbound
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.3 --ruc_variant ruc_dnskey --with_sig 1

# test knot
echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Testing Knot resolver against ruc_dnskey (w/o SIG)..."
python3 renew_resolver.py --resolver knot
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.4 --ruc_variant ruc_dnskey --with_sig 0

echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Testing Knot resolver against ruc_dnskey (w/ SIG)..."
python3 renew_resolver.py --resolver knot
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.4 --ruc_variant ruc_dnskey --with_sig 1

# test technitium
echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Testing Technitium resolver against ruc_dnskey (w/o SIG)..."
python3 renew_resolver.py --resolver technitium
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.5 --ruc_variant ruc_dnskey --with_sig 0

echo "Preparing nameserver..."
docker restart ruc-nameserver
sleep 5
echo "Testing Technitium resolver against ruc_dnskey (w/ SIG)..."
python3 renew_resolver.py --resolver technitium
docker exec ruc-attacker python3 /root/poc_scripts/ruc_poc.py --resolver_ip 172.22.1.5 --ruc_variant ruc_dnskey --with_sig 1