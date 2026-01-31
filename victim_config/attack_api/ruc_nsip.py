import sys
import time
import json
import argparse
from api import BASE_FOLDER
from dnslib import *
from dnslib.server import *

APEX='dnssec-ruc.xyz.'
TARGET='victim-rucnsip.'+APEX
TARGET_NSDOM='rucnsip.'+APEX
NAMESERVER_THREADS=1000
    
class NSNameserver:
    def __init__(self):
        with open(f'{BASE_FOLDER}/config.json') as f:
            config_dict=json.load(f)
        self.timestamp=config_dict[TARGET_NSDOM]['TIMESTAMP']
        self.nsip=config_dict[TARGET_NSDOM]['NSIP']
        self.nsip_bad=config_dict[TARGET_NSDOM]['NSIP_BAD']
        self.bad_ttl=config_dict[TARGET_NSDOM]['BAD_TTL']
        self.good_ttl=config_dict[TARGET_NSDOM]['GOOD_TTL']
        self.sig_inc_time=config_dict[TARGET_NSDOM]['SIGTIME']['SIG_INC']
        self.sig_exp_time=config_dict[TARGET_NSDOM]['SIGTIME']['SIG_EXP']
        self.rrsig_zsk_nsdom=config_dict[TARGET_NSDOM]['ZSK']['RRSIG']
        self.rrsig_ksk_nsdom=config_dict[TARGET_NSDOM]['KSK']['RRSIG']
        self.zsk_nsdom=config_dict[TARGET_NSDOM]['ZSK']['KEY']
        self.ksk_nsdom=config_dict[TARGET_NSDOM]['KSK']['KEY']
        self.tag_zsk_nsdom=config_dict[TARGET_NSDOM]['ZSK']['TAG']
        self.tag_ksk_nsdom=config_dict[TARGET_NSDOM]['KSK']['TAG']
        self.alg_zsk_nsdom=config_dict[TARGET_NSDOM]['ZSK']['ALG']
        self.alg_ksk_nsdom=config_dict[TARGET_NSDOM]['KSK']['ALG']

    def resolve(self,request,handler):
        reply=request.reply()
        qname=str(request.q.qname)
        qtype=int(str(request.q.qtype))

        try:
            domain=qname.lower()
            if domain=='ns1.'+TARGET_NSDOM:
                rr_a=RR(rname=qname,rtype=1,ttl=self.good_ttl,rdata=A(self.nsip))
                reply.add_answer(rr_a)
                reply.header.rcode=getattr(RCODE,'NOERROR')
            
            elif domain=='ns.'+TARGET_NSDOM:
                rr_a=RR(rname=qname,rtype=1,ttl=self.bad_ttl,rdata=A(self.nsip_bad))
                reply.add_answer(rr_a)
                reply.header.rcode=getattr(RCODE,'NOERROR')
            
            elif domain==TARGET_NSDOM:
                zsk_rr=RR(rname=qname,rtype=48,ttl=self.good_ttl,rdata=DNSKEY(flags=256,protocol=3,algorithm=8,key=base64.b64decode(self.zsk_nsdom)))
                ksk_rr=RR(rname=qname,rtype=48,ttl=self.good_ttl,rdata=DNSKEY(flags=257,protocol=3,algorithm=8,key=base64.b64decode(self.ksk_nsdom)))
                rrsig_ksk=RR(rname=qname,rtype=46,ttl=self.good_ttl,rdata=RRSIG(covered=48,algorithm=self.alg_ksk_nsdom,labels=3,orig_ttl=self.good_ttl,
                                                                                sig_exp=self.sig_exp_time,
                                                                                sig_inc=self.sig_inc_time,
                                                                                key_tag=self.tag_ksk_nsdom,
                                                                                name=TARGET_NSDOM,
                                                                                sig=base64.b64decode(self.rrsig_ksk_nsdom)))
                reply.add_answer(zsk_rr)
                reply.add_answer(ksk_rr)
                reply.add_answer(rrsig_ksk)
                reply.header.rcode=getattr(RCODE,'NOERROR')

            elif domain==TARGET:
                rr_ns=RR(rname=qname,rtype=2,ttl=self.bad_ttl,rdata=NS('ns.'+TARGET_NSDOM))
                reply.add_answer(rr_ns)
                reply.header.rcode=getattr(RCODE,'NOERROR')
                
            else:
                reply.header.rcode=getattr(RCODE,'NXDOMAIN')
            
            reply.header.set_aa(1)
            reply.header.set_ra(0)
            opt_record=EDNS0(flags='do',udp_len=4096)
            reply.add_ar(opt_record)
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