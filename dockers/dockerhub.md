# Ready-made Docker Images from DockerHub
We provide ready-made Docker images for the tested DNS resolvers, victim domain's nameserver and the RUC attacker. Use the following commands to pull the images from DockerHub and tag them for local use.

## DNS resolver software
```bash
docker pull ohmyzshhh/ruc_poc:bind9.20.3
docker pull ohmyzshhh/ruc_poc:powerdns5.1.3
docker pull ohmyzshhh/ruc_poc:unbound1.22.0
docker pull ohmyzshhh/ruc_poc:knot5.7.4
docker pull ohmyzshhh/ruc_poc:technitium13.1

docker tag ohmyzshhh/ruc_poc:bind9.20.3 ruc-bind:9.20.3
docker tag ohmyzshhh/ruc_poc:powerdns5.1.3 ruc-powerdns:5.1.3
docker tag ohmyzshhh/ruc_poc:unbound1.22.0 ruc-unbound:1.22.0
docker tag ohmyzshhh/ruc_poc:knot5.7.4 ruc-knot:5.7.4
docker tag ohmyzshhh/ruc_poc:technitium13.1 ruc-technitium:13.1
```

## Victim domain's nameserver
### Linux-based resolvers
```bash
docker pull ohmyzshhh/ruc_poc:nameserver
docker tag ohmyzshhh/ruc_poc:nameserver nameserver:ruc
```

### Microsoft DNS resolver
```bash
docker pull ohmyzshhh/ruc_poc:nameserver-ms
docker tag ohmyzshhh/ruc_poc:nameserver-ms nameserver:ruc-ms
```

## RUC attacker
```bash
docker pull ohmyzshhh/ruc_poc:attacker
docker tag ohmyzshhh/ruc_poc:attacker attacker:ruc
```
