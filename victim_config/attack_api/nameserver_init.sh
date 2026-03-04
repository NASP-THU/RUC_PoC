#!/bin/bash

# start nameserver service
service named start
echo "===== BIND authoritative nameserver started. ====="

# start RUC attacker API
python3 /root/attack_api/config_ruc_domains.py --apex_zone "${APEX_ZONE}"
python3 /root/attack_api/api.py --apex_zone "${APEX_ZONE}"
