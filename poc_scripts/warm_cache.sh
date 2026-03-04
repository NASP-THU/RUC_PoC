#!/bin/bash     

# We have noticed that for some resolvers (e.g., BIND), resolving the out-of-zone delegations of the apex domain may cause accidental response failure.
# Hence, we fill the nameserver IP addresses into the resolver cache in advance.
# Note that the cache warming is intended to eliminate the interference to the reproduction results, and is irrelavant to the existence of the RUC vulnerability.

for i in {1..5}
do
    docker exec ruc-attacker dig +dnssec @$1 grannbo.ns.cloudflare.com
    docker exec ruc-attacker dig +dnssec @$1 koa.ns.cloudflare.com
done
