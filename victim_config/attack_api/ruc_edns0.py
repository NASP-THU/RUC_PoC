import sys
import json
import time
import datetime
from api import BASE_FOLDER
from dnslib import *
from dnslib.server import *

APEX='dnssec-ruc.xyz.'
TARGET='victim-rucedns0.'+APEX
NAMESERVER_THREADS=1000

class NSNameserver:
    def __init__(self):
        with open(f'{BASE_FOLDER}/config.json') as f:
            config_dict=json.load(f)
        self.timestamp=config_dict[TARGET]['TIMESTAMP']
        self.nsip=config_dict[TARGET]['NSIP']
        self.good_ttl=config_dict[TARGET]['GOOD_TTL']
        self.bad_ttl=config_dict[TARGET]['BAD_TTL']
        self.sig_inc_time=config_dict[TARGET]['SIGTIME']['SIG_INC']
        self.sig_exp_time=config_dict[TARGET]['SIGTIME']['SIG_EXP']
        self.rrsig_soa=config_dict[TARGET]['RRSIG_SOA']
        self.rrsig_nsec=config_dict[TARGET]['RRSIG_NSEC']
        self.rrsig_zsk=config_dict[TARGET]['ZSK']['RRSIG']
        self.rrsig_ksk=config_dict[TARGET]['KSK']['RRSIG']
        self.zsk=config_dict[TARGET]['ZSK']['KEY']
        self.ksk=config_dict[TARGET]['KSK']['KEY']
        self.tag_zsk=config_dict[TARGET]['ZSK']['TAG']
        self.tag_ksk=config_dict[TARGET]['KSK']['TAG']
        self.alg_zsk=config_dict[TARGET]['ZSK']['ALG']
        self.alg_ksk=config_dict[TARGET]['KSK']['ALG']
        
    def resolve(self,request,handler):
        reply=request.reply()
        qname=str(request.q.qname)
        qtype=int(str(request.q.qtype))
        src_ip=handler.client_address[0]
        try:
            domain=qname.lower()
            if domain.endswith(TARGET):
                if qtype==48:
                    zsk_rr=RR(rname=qname,rtype=48,ttl=self.good_ttl,rdata=DNSKEY(flags=256,protocol=3,algorithm=8,key=base64.b64decode(self.zsk)))
                    ksk_rr=RR(rname=qname,rtype=48,ttl=self.good_ttl,rdata=DNSKEY(flags=257,protocol=3,algorithm=8,key=base64.b64decode(self.ksk)))
                    rrsig_ksk=RR(rname=qname,rtype=46,ttl=self.good_ttl,rdata=RRSIG(covered=48,algorithm=self.alg_ksk,labels=3,orig_ttl=self.good_ttl,
                                                                                    sig_exp=self.sig_exp_time,
                                                                                    sig_inc=self.sig_inc_time,
                                                                                    key_tag=self.tag_ksk,
                                                                                    name=TARGET,
                                                                                    sig=base64.b64decode(self.rrsig_ksk)))
                    reply.add_answer(zsk_rr)
                    reply.add_answer(ksk_rr)
                    reply.add_answer(rrsig_ksk)

                    opt_record=EDNS0(flags='do',udp_len=4096)
                    reply.add_ar(opt_record)
                    reply.header.rcode=getattr(RCODE,'NOERROR')

                else:
                    rr_soa=RR(rname=TARGET,rtype=6,ttl=self.good_ttl,rdata=SOA("ns.rucedns0."+APEX,"admin."+APEX,(int(self.timestamp+'01'),3600,1800,129600,600)))
                    rrsig_soa=RR(rname=TARGET,rtype=46,ttl=self.good_ttl,rdata=RRSIG(covered=6,algorithm=self.alg_zsk,labels=3,orig_ttl=self.good_ttl,
                                                                                    sig_exp=self.sig_exp_time,
                                                                                    sig_inc=self.sig_inc_time,
                                                                                    key_tag=self.tag_zsk,
                                                                                    name=TARGET,
                                                                                    sig=base64.b64decode(self.rrsig_soa)))
                    rr_nsec=RR(rname=TARGET,rtype=47,ttl=self.good_ttl,rdata=NSEC(label=TARGET,rrlist=['A','NS','SOA','RRSIG','NSEC','DNSKEY']))
                    rrsig_nsec=RR(rname=TARGET,rtype=46,ttl=self.good_ttl,rdata=RRSIG(covered=47,algorithm=self.alg_zsk,labels=3,orig_ttl=self.good_ttl,
                                                                                    sig_exp=self.sig_exp_time,
                                                                                    sig_inc=self.sig_inc_time,
                                                                                    key_tag=self.tag_zsk,
                                                                                    name=TARGET,
                                                                                    sig=base64.b64decode(self.rrsig_nsec)))
                    reply.add_auth(rr_soa)
                    reply.add_auth(rrsig_soa)
                    reply.add_auth(rr_nsec)
                    reply.add_auth(rrsig_nsec)
                    
                    # Remove EDNS0 OPT record in the additional section of the DNS response
                    # opt_record=EDNS0(flags='do',udp_len=4096)
                    # reply.add_ar(opt_record)

                    # To align with the "additional count" in the response header, add an arbitrary glue record
                    rr_a=RR(rname='ns.'+TARGET,rtype=1,ttl=self.good_ttl,rdata=A(self.nsip))
                    reply.add_ar(rr_a)
                    
                    reply.header.rcode=getattr(RCODE,'NXDOMAIN')
                    print(src_ip,datetime.datetime.today(),'NXDOMAIN (without OPT) sent.')

            else:
                opt_record=EDNS0(flags='do',udp_len=4096)
                reply.add_ar(opt_record)
                reply.header.rcode=getattr(RCODE,'NXDOMAIN')
            
            reply.header.set_aa(1)
            reply.header.set_ra(0)
            return reply
        
        except:
            print('exception:',qname,qtype)

            reply.header.rcode=getattr(RCODE,'NXDOMAIN')
            reply.header.set_aa(1)
            reply.header.set_ra(0)

            opt_record=EDNS0(flags='do',udp_len=4096)
            reply.add_ar(opt_record)

            return reply
    
def main():
    nameserver=NSNameserver()
    
    dns_server=DNSServer(nameserver,port=53,address='0.0.0.0')
    for _ in range(NAMESERVER_THREADS):
        dns_server.start_thread()
    
    try:
        while True:
            time.sleep(600)
    except KeyboardInterrupt:
        sys.exit(0)

if __name__=='__main__':
    main()