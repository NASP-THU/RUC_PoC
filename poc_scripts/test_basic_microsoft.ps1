Restart-Service -Name "DNS" -Force
python basic_test.py --resolver_ip 127.0.0.1
Start-Sleep -Seconds 10