import random
import string
import datetime
import ipaddress

from dnslib import *
from dnslib.server import *

def generate_random_string(length=10):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choices(characters, k=length))
    return random_string

def send_dns_request(resolver_ip,domain,rtype,cd,ad,opt,do):
    q=DNSRecord.question(domain,qtype=rtype,qclass="IN")
    q.header.cd=cd
    q.header.ad=ad
    if opt==1:
        if do==1:
            opt_record=EDNS0(flags='do',udp_len=4096)
        else:
            opt_record=EDNS0(udp_len=4096)
        q.add_ar(opt_record)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(q.pack(),(resolver_ip,53))
        try:
            response, _ = sock.recvfrom(4096)
            d=DNSRecord.parse(response)
            return d
        except:
            return '[*] dns request timeout'
    return '[*] dns request no output'

def log_dns_output(content,log_file):
    fw=open(log_file,'a')
    fw.write('*** '+str(datetime.datetime.today())+'\n')
    fw.write(content+'\n')
    fw.write('*** end ***\n\n')
    fw.close()

def has_ip_answer(line):
    line=line.replace('\t',' ')
    items_tmp=line.strip().split(' ')
    items=list()
    for item in items_tmp:
        if item!='':
            items.append(item)
    ip=items[-1]
    try:
        ipaddress.IPv4Address(ip)
        return True
    except:
        return False

def get_resolver(resolver_ip):
    resolver_ip_dict={
        '172.22.1.1':'BIND-9.20.3',
        '172.22.1.2':'PowerDNS-5.1.3',
        '172.22.1.3':'Unbound-1.22.0',
        '172.22.1.4':'Knot Resolver-5.7.4',
        '172.22.1.5':'Technitium-13.1',
        '127.0.0.1':'Microsoft DNS-2022'
    }
    if resolver_ip in resolver_ip_dict.keys():
        return resolver_ip_dict[resolver_ip]
    else:
        return '-'