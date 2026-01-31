#!/bin/bash

# start nameserver service
SERVICE_FILE="/etc/systemd/system/named.service"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root or with sudo."
    exit 1
fi

cat <<EOL > /etc/systemd/system/named.service
[Unit]
Description=BIND DNS Server
After=network.target

[Service]
Type=forking
ExecStart=/usr/sbin/named -u root
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/bin/kill -TERM \$MAINPID
PIDFile=/usr/local/var/run/named/named.pid
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOL

sudo systemctl daemon-reload
sudo systemctl enable named

sudo service named start
echo "===== BIND authoritative nameserver started. ====="

# start RUC attacker API
python3 /root/attack_api/config.py
python3 /root/attack_api/api.py