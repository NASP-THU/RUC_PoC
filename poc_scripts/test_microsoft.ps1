Write-Host "Testing Microsoft resolver against ruc_dnskey (w/o SIG)..."
Restart-Service -Name "DNS" -Force
python ruc_poc.py --resolver_ip 127.0.0.1 --ruc_variant ruc_dnskey --with_sig 0

Write-Host "Testing Microsoft resolver against ruc_dnskey (w/ SIG)..."
Restart-Service -Name "DNS" -Force
python ruc_poc.py --resolver_ip 127.0.0.1 --ruc_variant ruc_dnskey --with_sig 1

Write-Host "Testing Microsoft resolver against ruc_ds (w/o SIG)..."
Restart-Service -Name "DNS" -Force
python ruc_poc.py --resolver_ip 127.0.0.1 --ruc_variant ruc_ds --with_sig 0

Write-Host "Testing Microsoft resolver against ruc_ds (w/ SIG)..."
Restart-Service -Name "DNS" -Force
python ruc_poc.py --resolver_ip 127.0.0.1 --ruc_variant ruc_ds --with_sig 1

Write-Host "Testing Microsoft resolver against ruc_nsip..."
Restart-Service -Name "DNS" -Force
python ruc_poc.py --resolver_ip 127.0.0.1 --ruc_variant ruc_nsip

Write-Host "Testing Microsoft resolver against ruc_edns0..."
Restart-Service -Name "DNS" -Force
python ruc_poc.py --resolver_ip 127.0.0.1 --ruc_variant ruc_edns0

Write-Host "[*] Testing Microsoft resolver against RUC, done. "
Write-Host "[*] Please refer to the file ruc_test_result/log_ruc_test-microsoft.txt for the testing results." 
Start-Sleep -Seconds 30