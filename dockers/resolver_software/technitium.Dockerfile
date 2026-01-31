FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
ENV TECHNITIUM_VERSION="13.1"

# install dependencies
RUN apt-get update && apt-get install -y wget tar

# download app
WORKDIR /app
RUN wget https://download.technitium.com/dns/archive/${TECHNITIUM_VERSION}/DnsServerPortable.tar.gz -O /tmp/dns.tar.gz \
    && tar -xzvf /tmp/dns.tar.gz -C /app \
    && rm /tmp/dns.tar.gz

# start resolver service
EXPOSE 53/tcp 53/udp 5380
WORKDIR /root
ENTRYPOINT ["dotnet", "/app/DnsServerApp.dll"]
