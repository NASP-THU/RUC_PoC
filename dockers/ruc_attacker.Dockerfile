FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# install BIND latest version
RUN apt update && \
    apt install -y python3 python3-pip dnsutils

# install python dependencies
RUN pip3 install dnslib requests

WORKDIR /root/poc_scripts/
CMD ["tail", "-f", "/dev/null"]