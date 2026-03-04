# Test environment setup

## All-in-one setup script
### Linux-based resolvers
For the 5 Linux-based resolvers in our paper (i.e., BIND, PowerDNS, Unbound, Knot Resolver and Technitium), they are evaluated on a Linux (e.g., Ubuntu 22.04) host machine with the Docker Engine.

First, create a Docker network named `ruc-test-net` dedicated for the RUC test:
```bash
docker network create --subnet "172.22.0.0/16" ruc-test-net
```

After that, use the following commands to build Docker images and run containers for the tested resolvers, victim domains' nameserver and the RUC attacker, respectively:
```bash
# tested DNS resolvers
bash start_resolver.sh

# victim domains' nameserver
bash start_nameserver.sh

# RUC attacker
bash start_attacker.sh
```

Now the setup for the Linux-based resolvers has finished, and you can go to the basic test section to verify the setup. We also provide detailed explanations on the setup steps in the subsequent sections.

### Microsoft DNS resolver
For Microsoft DNS resolver, we provide a ready-made Windows Server virtual machine (VM) with Microsoft DNS service installed and DNSSEC enabled (see [Windows_Server_2022.ova](https://doi.org/10.5281/zenodo.15710349)). This file can be imported into common VM tools, e.g., [VMware Workstation](https://support.broadcom.com/group/ecx/productdownloads?subfamily=VMware%20Workstation%20Pro&freeDownloads=true). 

You can log in to the server as `Administrator` with password `RUC@Sec25`. We have put the scripts under `C:\Users\Administrator\Desktop\poc_scripts\` on the VM. All necessary python packages have already been installed.

Besides, the experiment requires another VM to serve as the authoritative nameserver of the RUC victim domains. This VM runs Ubuntu Server 22.04, and resides within the same VM network (e.g., `VMnet8` for the NAT network adapter) with the Windows Server VM. Please refer to the [manual](victim_config/ubuntu_vm.pdf) for the setup of the Ubuntu VM.

Clone this repository to the home directory of the Ubuntu VM. Then, run the script [nameserver_config_ms.sh](victim_config/nameserver_config_ms.sh) to configure the network interface and run the authoritative DNS service.
```bash
cd victim_config
sudo bash nameserver_config_ms.sh
```

Now the setup for evaluating Microsoft DNS resolver has finished, and you can go to the basic test section to verify the setup.

## Network configurations
All the Linux-based resolvers are evaluated within the Docker network `ruc-test-net`.

| Component                  | Vendor        | Version | Image name          | Container Name | Local IP Address |
|----------------------------|---------------|---------|---------------------|----------------|------------------|
| DNS resolver               | BIND          | 9.20.3  | ruc-bind:9.20.3     | ruc-bind       | 172.22.1.1       |
| DNS resolver               | PowerDNS      | 5.1.3   | ruc-powerdns:5.1.3  | ruc-powerdns   | 172.22.1.2       |
| DNS resolver               | Unbound       | 1.22.0  | ruc-unbound:1.22.0  | ruc-unbound    | 172.22.1.3       |
| DNS resolver               | Knot Resolver | 5.7.4   | ruc-knot:5.7.4      | ruc-knot       | 172.22.1.4       |
| DNS resolver               | Technitium    | 13.1    | ruc-technitium:13.1 | ruc-technitium | 172.22.1.5       |
| Victim domain's nameserver | BIND          | latest  | nameserver:ruc      | ruc-nameserver | 172.22.2.1       |
| RUC attacker               | -             | -       | attacker:ruc        | ruc-attacker   | 172.22.3.1       |

The Microsoft DNS resolver is evaluated within the local VM network (e.g., `VMnet8`).
| Component                  | Vendor        | Version | Local IP Address      |
|----------------------------|---------------|---------|-----------------------|
| Resolver software          | Microsoft     | 2022    | 127.0.0.1<sup>*</sup> |
| Victim domain's nameserver | BIND          | latest  | 192.168.45.70         |
| RUC attacker               | -             | -       | 127.0.0.1<sup>*</sup> |

<sup>*</sup>The RUC test is conducted directly on the Windows Server VM running the Microsoft DNS resolver.

## Detailed instructions on the environment setup
### DNS resolver software
First, build the Docker image of the tested DNS resolvers (except Microsoft DNS):
```bash
docker build -f dockers/resolver_software/bind.Dockerfile -t ruc-bind:9.20.3 .
docker build -f dockers/resolver_software/powerdns.Dockerfile -t ruc-powerdns:5.1.3 .
docker build -f dockers/resolver_software/unbound.Dockerfile -t ruc-unbound:1.22.0 .
docker build -f dockers/resolver_software/knot.Dockerfile -t ruc-knot:5.7.4 .
docker build -f dockers/resolver_software/technitium.Dockerfile -t ruc-technitium:13.1 .
```

Next, run a Docker container for each DNS resolver:
```bash
docker run -d --name ruc-bind --network ruc-test-net --ip 172.22.1.1 ruc-bind:9.20.3
docker run -d --name ruc-powerdns --network ruc-test-net --ip 172.22.1.2 ruc-powerdns:5.1.3
docker run -d --name ruc-unbound --network ruc-test-net --ip 172.22.1.3 ruc-unbound:1.22.0
docker run -d --name ruc-knot --network ruc-test-net --ip 172.22.1.4 ruc-knot:5.7.4
docker run -d --name ruc-technitium --network ruc-test-net --ip 172.22.1.5 ruc-technitium:13.1
```

For Microsoft DNS, if you intend to manually install Microsoft DNS service on a Windows Server VM and enable DNSSEC validation, please refer to the manual [microsoft_setup.pdf](dockers/resolver_software/microsoft/microsoft_setup.pdf) for detailed instructions.

### Victim domains and nameserver
We support the reproduction of the RUC attack using our controlled apex domain, `dnssec-ruc.xyz` and `dnssec-ruc-ms.xyz` (for Microsoft DNS). Each RUC attack variant corresponds to a specific subdomain under `dnssec-ruc.xyz` (or `dnssec-ruc-ms.xyz`) as the victim (detailed in [ruc_reproduction.md](ruc_reproduction.md)). 

The nameserver of subdomains under `dnssec-ruc.xyz` will be automatically resolved to `172.22.2.1`, i.e., the IP address of the local Docker container running as the victim authoritative nameserver. The nameserver of subdomains under `dnssec-ruc-ms.xyz` will be automatically resolved to `192.168.45.70`, i.e., the IP address of the local Ubuntu VM running as the victim domains' authoritative nameserver.

**Important note: The victim domains serve only for academic purposes, i.e., the reproduction of the RUC attack within the controlled environment. Any abuse of the domains or scripts for real-world attacks is strictly prohibited.**

First, build the Docker image of the local victim nameserver (or pull the ready-made image as in [dockerhub.md](dockers/dockerhub.md)):
```bash
docker build -f dockers/nameserver.Dockerfile --build-arg APEX_ZONE=dnssec-ruc.xyz -t nameserver:ruc .
```

Next, run a Docker container for the local nameserver of the victim domain:
```bash
docker run -d --name ruc-nameserver --network ruc-test-net --ip 172.22.2.1 nameserver:ruc
```

This nameserver runs the latest version of BIND to provide authoritative DNS service. It also runs an API for the RUC
attack, which is invoked by the attack script to simulate on-path response manipulations.

Please note that the RUC vulnerabilities of DNS resolvers are independent of specific victim domains. Besides, all resource records of the victim domains under our apex zones are transparent. Please refer to the apex zone file ([db.dnssec-ruc.xyz](victim_config/dnssec-ruc.xyz/db.dnssec-ruc.xyz) and [db.dnssec-ruc-ms.xyz](victim_config/dnssec-ruc-ms.xyz/db.dnssec-ruc-ms.xyz)) for the referral delegation records (e.g., NS, DS records) and zone files under [bind/](victim_config/bind/) for the authoritative records of the victim domains.

### RUC attacker
First, build the Docker image for the RUC attacker (or pull the ready-made image as in [dockerhub.md](dockers/dockerhub.md)):
```bash
docker build -f dockers/ruc_attacker.Dockerfile -t attacker:ruc .
```

Next, run a Docker container for the RUC attacker:
```bash
docker run -it --name ruc-attacker --network ruc-test-net --ip 172.22.3.1 -v "$(pwd)/poc_scripts/:/root/poc_scripts/" attacker:ruc
```

This command will mount the PoC script folder ([poc_scripts/](poc_scripts/)) to `/root/poc_scripts` in the container.

### Pull ready-made Docker images from DockerHub
Alternatively, you can pull the ready-made Docker images from DockerHub (see [dockerhub.md](dockers/dockerhub.md)). 

## Basic test for environment setup
To verify the environment setup, we issue DNS queries from the container of RUC attacker towards the container of each tested resolver, requesting a DNSSEC-signed domain hosted on the victim domains' nameserver. The outputs of the following commands will be stored in `poc_scripts/basic_test_result/log_basic_test.csv`. All entries should be tagged as `succeed` if the setup is correct, i.e., the tested resolvers is running with DNSSEC validation enabled, and the nameserver is also functioning properly.

```bash
cd poc_scripts
bash test_basic.sh
```

For Microsoft DNS, on the Windows Server VM, run the scripts `poc_scripts/test_basic_microsoft.ps1` using PowerShell, where the outputs will be stored in `poc_scripts/basic_test_result/log_basic_test-microsoft.csv`. Similarly, there should be `succeed` in the output, indicating a successful environment setup.
