# Test environment setup

## Docker network configuration
First, create a docker network named `ruc-test-net` for the RUC vulnerability test:
```bash
docker network create --subnet "172.22.0.0/16" ruc-test-net
```

We assign an IP address for each DNS component involved in the test according to the following table:

| Service Type               | Vendor        | Version | Image name          | Container Name | Local IP Address |
|----------------------------|---------------|---------|---------------------|----------------|------------------|
| Resolver software          | BIND          | 9.20.3  | ruc-bind:9.20.3     | ruc-bind       | 172.22.1.1       |
| Resolver software          | PowerDNS      | 5.1.3   | ruc-powerdns:5.1.3  | ruc-powerdns   | 172.22.1.2       |
| Resolver software          | Unbound       | 1.22.0  | ruc-unbound:1.22.0  | ruc-unbound    | 172.22.1.3       |
| Resolver software          | Knot Resolver | 5.7.4   | ruc-knot:5.7.4      | ruc-knot       | 172.22.1.4       |
| Resolver software          | Technitium    | 13.1    | ruc-technitium:13.1 | ruc-technitium | 172.22.1.5       |
| Resolver software          | Microsoft DNS | 2022    | -                   | -              | 127.0.0.1[*]     |
| Victim domain's nameserver | -             | -       | nameserver:ruc      | ruc-nameserver | 172.22.2.1       |
| RUC attacker               | -             | -       | attacker:ruc        | ruc-attacker   | 172.22.3.1       |

[*] As both Microsoft DNS service and the testing scripts are installed locally on a Windows Server virtual machine, the resolver's IP address in the test is `127.0.0.1`.

## All-in-one setup script
After creating the docker network, you can use the following commands to build docker images and run containers for all the tested resolvers (except Microsoft DNS), victim domains' nameserver and the RUC attacker in one go:
```bash
# tested DNS resolvers
bash start_resolver.sh

# victim domains' nameserver
bash start_nameserver.sh

# RUC attacker
bash start_attacker.sh
```

For Microsoft DNS, we provide a ready-made Windows Server virtual machine with Microsoft DNS service installed and DNSSEC enabled (see [Windows_Server_2022.ova](https://doi.org/10.5281/zenodo.15710349)). This file can be imported into virtual machine tools such as VMware Workstation or VirtualBox. You can log in to the server as `Administrator` with password `RUC@Sec25`. We have put the scripts under `C:\Users\Administrator\Desktop\poc_scripts\` on the virtual machine. All necessary python packages have already been installed.

If you want to see the detailed, specific explanations of the setup steps, please refer to the following section.

## Detailed instructions on environment setup
### DNS resolver software
You can run the following commands to build a docker image for each DNS resolver software running on Linux OS (i.e., except Microsoft DNS):
```bash
docker build -f dockers/resolver_software/bind.Dockerfile -t ruc-bind:9.20.3 .
docker build -f dockers/resolver_software/powerdns.Dockerfile -t ruc-powerdns:5.1.3 .
docker build -f dockers/resolver_software/unbound.Dockerfile -t ruc-unbound:1.22.0 .
docker build -f dockers/resolver_software/knot.Dockerfile -t ruc-knot:5.7.4 .
docker build -f dockers/resolver_software/technitium.Dockerfile -t ruc-technitium:13.1 .
```

Next, start docker containers using the following commands:
```bash
docker run -d --name ruc-bind --network ruc-test-net --ip 172.22.1.1 ruc-bind:9.20.3
docker run -d --name ruc-powerdns --network ruc-test-net --ip 172.22.1.2 ruc-powerdns:5.1.3
docker run -d --name ruc-unbound --network ruc-test-net --ip 172.22.1.3 ruc-unbound:1.22.0
docker run -d --name ruc-knot --network ruc-test-net --ip 172.22.1.4 ruc-knot:5.7.4
docker run -d --name ruc-technitium --network ruc-test-net --ip 172.22.1.5 ruc-technitium:13.1
```

For Microsoft DNS, if you intend to manually install Microsoft DNS service on a Windows Server virtual machine and enable DNSSEC validation, please refer to the manual [microsoft_setup.pdf](dockers/resolver_software/microsoft/microsoft_setup.pdf) for detailed instructions.

### Victim domains and nameserver
We support the reproduction of the RUC attack using our controlled apex domain, `dnssec-ruc.xyz` and `dnssec-ruc-ms.xyz` (for Microsoft DNS). Each RUC attack variant corresponds to a specific subdomain under `dnssec-ruc.xyz` (or `dnssec-ruc-ms.xyz`) as the victim (detailed in [ruc_reproduction.md](ruc_reproduction.md)). 

The nameserver of subdomains under `dnssec-ruc.xyz` will be automatically resolved to `172.22.2.1`, i.e., the IP address of a local docker container running the victim authoritative nameserver. The nameserver of subdomains under `dnssec-ruc-ms.xyz` will be automatically resolved to `47.251.171.85`, i.e., our own DNS server dedicated to testing Microsoft DNS. 

**Important note: The victim domains serve only for academic purposes, i.e., the reproduction of the RUC attack within the controlled environment. Any abuse of the domains or scripts for real-world attacks is strictly prohibited.**

To build a docker image for the local victim nameserver, use the following command (or pull the ready-made image as in [dockerhub.md](dockers/dockerhub.md)):
```bash
docker build -f dockers/nameserver.Dockerfile -t nameserver:ruc .
```

Run a docker container for the local nameserver of the victim domain:
```bash
docker run -d --name ruc-nameserver --network ruc-test-net --ip 172.22.2.1 nameserver:ruc
```
This nameserver runs the latest version of BIND to provide authoritative DNS service. It also runs an API for the RUC
attack, which is invoked by the attack script to simulate on-path response manipulations. In this case, the RUC vulnerabilities of DNS resolvers are independent of specific victim domains, and all resource records of the victim domains under our apex zones are transparent. Please refer to the apex zone file [apex_zone.txt](victim_config/apex_zone.txt) for the referral delegation records (e.g., NS, DS records) and zone files under [bind/](victim_config/bind/) for the authoritative records of the victim domains.

### RUC attacker
Build the docker image for the RUC attacker (or pull the ready-made image as in [dockerhub.md](dockers/dockerhub.md)):
```bash
docker build -f dockers/ruc_attacker.Dockerfile -t attacker:ruc .
```

Next, run a docker container for the RUC attacker:
```bash
docker run -it --name ruc-attacker --network ruc-test-net --ip 172.22.3.1 -v "$(pwd)/poc_scripts/:/root/poc_scripts/" attacker:ruc
```

This command will mount the PoC scripts ([poc_scripts/](poc_scripts/)) under the `/root/` directory in the container.

### Pull ready-made docker images from DockerHub
Alternatively, you can pull the ready-made docker image of each resolver software (except Microsoft DNS) from DockerHub (see [dockerhub.md](dockers/dockerhub.md)). 

## Basic test for environment setup
For basic test, we issue DNS queries from the container of RUC attacker towards the container of each tested resolver, requesting a DNSSEC-signed domain hosted on the victim domains' nameserver. The outputs of the following commands will be stored in `poc_scripts/basic_test_result/log_basic_test.csv`. All entries should be tagged as `succeed` if the setup is correct, i.e., the tested resolvers is running with DNSSEC validation enabled, and the nameserver is also functioning properly.

```bash
cd poc_scripts
bash test_basic.sh
```

For Microsoft DNS, on the Windows Server virtual machine, run the scripts `poc_scripts/test_basic_microsoft.ps1` using PowerShell, where the outputs will be stored in `poc_scripts/basic_test_result/log_basic_test-microsoft.csv`. Similarly, there should be `succeed` in the output, indicating a successful environment setup.