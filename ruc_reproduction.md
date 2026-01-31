# Reproduction of the RUC attack

This document provides detailed instructions on how to reproduce the three variants of the RUC attack, namely RUC<sub>SEC</sub> (including RUC<sub>DNSKEY</sub> and RUC<sub>DS</sub>), RUC<sub>NSIP</sub> and RUC<sub>EDNS0</sub>.

## Victim domains
All victim domains are under our controlled apex zone, `dnssec-ruc.xyz` (for Microsoft DNS, the apex is `dnssec-ruc-ms.xyz`). The detailed information of each victim domain is indicated in the following table:

| RUC variant          | Victim domain            | Associated domain   | Exploited unvalidated cache                                              | Valid IP address |
|----------------------|--------------------------|---------------------|--------------------------------------------------------------------------|------------------|
| RUC<sub>DNSKEY</sub> | victim-rucdnskey.{APEX}  | -                   | DNSKEY of victim-rucdnskey.{APEX}                                        | 10.0.1.1         |
| RUC<sub>DS</sub>     | sub.victim-rucds.{APEX}  | victim-rucds.{APEX} | DS of sub.victim-rucds.{APEX} (from the parent zone victim-rucds.{APEX}) | 10.0.1.2         |
| RUC<sub>NSIP</sub>   | victim-rucnsip.{APEX}    | rucnsip.{APEX}      | IP of victim-rucnsip.{APEX}'s nameserver, ns.rucnsip.{APEX}              | 10.0.2.1         |
| RUC<sub>EDNS0</sub>  | victim-rucedns0.{APEX}   | -                   | EDNS0 capability of victim-rucedns0.{APEX}'s nameserver host             | 10.0.3.1         |

You can refer to the apex zone file [apex_zone.txt](victim_config/apex_zone.txt) for the referral delegation records (e.g., NS, DS records) and zone files under [bind/](victim_config/bind/) for the authoritative records of the victim domains.

**Important note: The victim domains serve only for academic purposes, i.e., the reproduction of the RUC attack within the controlled environment. Any abuse of the domains or scripts for real-world attacks is strictly prohibited.**

## Workflow of the PoC script
The PoC script of the RUC attack is [ruc_poc.py](poc_scripts/ruc_poc.py). The workflow of this script is as follows:
1. A response manipulation program (see [attack_api/](victim_config/attack_api/)) is started on the authoritative nameserver of the victim domain (i.e., the local nameserver `172.22.2.1`) to simulate a (short-lived) on-path attacker (`config_authns('inject')` in the PoC script). 
2. The attacker injects forged, unvalidated data into the cache of the target resolver, e.g., DNSKEY without RRSIG for an RUC<sub>DNSKEY</sub> attack (`inject_cache()` in the PoC script).
3. The manipulation program at the nameserver side is stopped, and the original, benign service of the nameserver is resumed (`config_authns('resume')` in the PoC script).
4. The ordinary client sends routine DNS queries demanding DNSSEC validation to the target resolver. Responses from the resolver are logged and checked if they carry valid answers. If no answer is returned (i.e., SERVFAIL or timeout), the resolver is vulnerable to the corresponding RUC attack variant (`verify_dos()` in the PoC script).

## Test of each RUC variant (all resolvers in one go)
You can test the vulnerabilities of all resolvers against each RUC variant using the following scripts. All the scripts should be executed under the folder `poc_scripts/`, i.e., after the command `cd poc_scripts`.

For RUC<sub>DNSKEY</sub>:
```python
bash test_ruc_dnskey.sh
```

For RUC<sub>DS</sub>:
```python
bash test_ruc_ds.sh
```

For RUC<sub>NSIP</sub>:
```python
bash test_ruc_nsip.sh
```

For RUC<sub>EDNS0</sub>:
```python
bash test_ruc_edns0.sh
```

For Microsoft DNS, you can execute the script `C:\Users\Administrator\Desktop\poc_scripts\test_microsoft.ps1` using PowerShell on the Windows Server virtual machine. The script will test the vulnerabilities of Microsoft DNS resolver against all of the RUC attack variants. As the Microsoft DNS service has been installed locally, the resolver's IP address in this test is `127.0.0.1`.

The test results will be logged in the file `poc_scripts/ruc_test_result/log_ruc_test.csv` (or `poc_scripts/ruc_test_result/log_ruc_test-microsoft.csv` for Microsoft DNS), with each line in the following format:
```text
{resolver software}|{resolver IP}|{RUC variant}|{with RRSIG}|{vulnerable}|{query failure rate}
```
The field `vulnerable` indicates the vulnerability of the resolver against the corresponding attack variant. All the test results should be consistent with Table 2 in Section 5.1 of our main paper. You can also compare the test results with the expected outputs under [expected_test_result](`poc_scripts/expected_test_result`). Note that the deviation in query failure rate (i.e., the last field of each line) might be due to the transient negative cache of the tested resolver, while the resolvers vulnerable to RUC should all have a failure rate of 100%.

## Test of each RUC variant (breaking down to a specified resolver)
If you are interested in a specific resolver, you can use the following commands to specify the resolver and inspect its behavior under a certain attack variant in detail. All of the following commands are executed within the docker container of the RUC attacker. Make sure that the testing environment demonstrated in [environment_setup.md](environment_setup.md) has been properly-configured. Note that resolver containers should be restarted to flush the cache when testing each RUC variant, in order to prevent interference between testings.

Input description:
- `resolver_ip`: local IP address of the target resolver (e.g., `172.22.1.1` for BIND)
- `ruc_variant`: tested RUC variant (ruc_dnskey, ruc_ds, ruc_nsip, or ruc_edns0)
- `with_sig`: ways to modify RRSIG in the response (only applicable to ruc_dnskey and ruc_ds), 0 for removing the RRSIG, 1 for manipulating some bits of the RRSIG

The raw DNS responses from the target resolver are dumped under the folder `poc_scripts/ruc_test_result_raw/{resolver_ip}/{ruc_variant}/{with_sig}/`.
The number of rounds, time interval of cache injection and ordinary client queries can be configured in [config.json](poc_scripts/config.json).

### RUC<sub>DNSKEY</sub>
Command: 
```python
python3 /root/poc_scripts/ruc_poc.py --resolver_ip X.X.X.X --ruc_variant ruc_dnskey --with_sig 0
```
Description: The attacker queries the target resolver for the DNSKEY of the victim domain via troubleshooting queries, and modify the RRSIG in the returned response (either removing or manipulating bits). The resolver caches the unvalidated DNSKEY record and reuses it when an ordinary client queries for the victim domain's A record. Due to the unvalidated DNSKEY, the victim domain's DNSSEC chain of trust cannot pass validation, resulting in SERVFAIL response. The vulnerable resolver will not discard the unvalidated DNSKEY and continuously encounter resolution failure, until the TTL of the DNSKEY expires.

Expected output of vulnerable resolver: 
```
[+] The tested resolver X.X.X.X is vulnerable to ruc_dnskey. Query failure rate: 100.00%
```

### RUC<sub>DS</sub>
Command: 
```python
python3 /root/poc_scripts/ruc_poc.py --resolver_ip X.X.X.X --ruc_variant ruc_ds --with_sig 0
```
Description: The attacker queries the target resolver for the DS of the victim domain via troubleshooting queries, and modify the RRSIG in the returned response (either removing or manipulating bits). The resolver caches the unvalidated DS record and reuses it when an ordinary client queries for the victim domain's A record. Due to the unvalidated DS, the victim domain's DNSSEC chain of trust cannot pass validation, resulting in SERVFAIL response. The vulnerable resolver will not discard the unvalidated DS and continuously encounter resolution failure, until the TTL of the DS expires.

Expected output of vulnerable resolver: 
```
[+] The tested resolver X.X.X.X is vulnerable to ruc_ds. Query failure rate: 100.00%
```

### RUC<sub>NSIP</sub>
Command: 
```python
python3 /root/poc_scripts/ruc_poc.py --resolver_ip X.X.X.X --ruc_variant ruc_nsip
```
Description: The attacker queries the target resolver for the IP address (i.e., A record) of the victim domain's nameserver via troubleshooting queries, and inject a forged, unvalidated A record for the nameserver. The resolver caches the unvalidated nameserver A record and reuses it when an ordinary client queries for the victim domain. Due to the unvalidated nameserver IP, the resolver cannot obtain authoritative records for the victim domain, resulting in query timeout or SERVFAIL response. The vulnerable resolver will not discard the unvalidated nameserver IP and continuously encounter resolution failure, until the TTL of the forged A record expires.

Expected output of vulnerable resolver: 
```
[+] The tested resolver X.X.X.X is vulnerable to ruc_nsip. Query failure rate: 100.00%
```

### RUC<sub>EDNS0</sub>
Command: 
```python
python3 /root/poc_scripts/ruc_poc.py --resolver_ip X.X.X.X --ruc_variant ruc_edns0
```
Description: The attacker queries the target resolver for a non-existent subdomain under the victim domain via troubleshooting queries, and strips off the EDNS0 OPT record in the returned response. The resolver caches the information that the nameserver host of the victim domain is not EDNS0-capable, and stops adding OPT in subsequent queries to this host. When an ordinary client queries for the victim domain's A record, the nameserver host considers that the resolver does not support DNSSEC, hence does not respond with the necessary RRSIG records. Due to missing RRSIG, the victim domain's DNSSEC chain of trust cannot pass validation, resulting in SERVFAIL response. The vulnerable resolver will continuously query the nameserver host without OPT and encounter resolution failure, until it reaches the EDNS0 status refresh period.

Expected output of vulnerable resolver: 
```
[+] The tested resolver X.X.X.X is vulnerable to ruc_edns0. Query failure rate: 100.00%
```
