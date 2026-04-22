import sys
import time
import json
import argparse
from dnslib import *
from dnslib.server import *

class RUCNSIP_Nameserver:
    def __init__(self,apex_zone):
        with open('config_subdomains.json') as f:
            config_dict=json.load(f)

        self.target=config_dict['subdomains']['ruc_nsip']+'.'+apex_zone+'.'
        self.target_nsdom=config_dict['subdomains']['ruc_nsip_nsdom']+'.'+apex_zone+'.'

        self.timestamp=config_dict[self.target_nsdom]['TIMESTAMP']
        self.nsip=config_dict[self.target_nsdom]['NSIP']
        self.nsip_bad=config_dict[self.target_nsdom]['NSIP_BAD']
        self.ttl=config_dict[self.target_nsdom]['TTL']
        self.sig_inc_time=config_dict[self.target_nsdom]['SIGTIME']['SIG_INC']
        self.sig_exp_time=config_dict[self.target_nsdom]['SIGTIME']['SIG_EXP']
        self.rrsig_zsk_nsdom=config_dict[self.target_nsdom]['ZSK']['RRSIG']
        self.rrsig_ksk_nsdom=config_dict[self.target_nsdom]['KSK']['RRSIG']
        self.zsk_nsdom=config_dict[self.target_nsdom]['ZSK']['KEY']
        self.ksk_nsdom=config_dict[self.target_nsdom]['KSK']['KEY']
        self.tag_zsk_nsdom=config_dict[self.target_nsdom]['ZSK']['TAG']
        self.tag_ksk_nsdom=config_dict[self.target_nsdom]['KSK']['TAG']
        self.alg_zsk_nsdom=config_dict[self.target_nsdom]['ZSK']['ALG']
        self.alg_ksk_nsdom=config_dict[self.target_nsdom]['KSK']['ALG']

        self.nameserver_threads=config_dict['nameserver_threads']

    def resolve(self,request,handler):
        reply=request.reply()
        qname=str(request.q.qname)
        qtype=int(str(request.q.qtype))

        try:
            domain=qname.lower()
            if domain=='ns1.'+self.target_nsdom:
                rr_a=RR(rname=qname,rtype=1,ttl=self.ttl,rdata=A(self.nsip))
                reply.add_answer(rr_a)
                reply.header.rcode=getattr(RCODE,'NOERROR')
            
            elif domain=='ns.'+self.target_nsdom:
                rr_a=RR(rname=qname,rtype=1,ttl=self.ttl,rdata=A(self.nsip_bad))
                reply.add_answer(rr_a)
                reply.header.rcode=getattr(RCODE,'NOERROR')
            
            elif domain==self.target_nsdom:
                zsk_rr=RR(rname=qname,rtype=48,ttl=self.ttl,rdata=DNSKEY(flags=256,protocol=3,algorithm=8,key=base64.b64decode(self.zsk_nsdom)))
                ksk_rr=RR(rname=qname,rtype=48,ttl=self.ttl,rdata=DNSKEY(flags=257,protocol=3,algorithm=8,key=base64.b64decode(self.ksk_nsdom)))
                rrsig_ksk=RR(rname=qname,rtype=46,ttl=self.ttl,rdata=RRSIG(covered=48,algorithm=self.alg_ksk_nsdom,labels=3,orig_ttl=self.ttl,
                                                                                sig_exp=self.sig_exp_time,
                                                                                sig_inc=self.sig_inc_time,
                                                                                key_tag=self.tag_ksk_nsdom,
                                                                                name=self.target_nsdom,
                                                                                sig=base64.b64decode(self.rrsig_ksk_nsdom)))
                reply.add_answer(zsk_rr)
                reply.add_answer(ksk_rr)
                reply.add_answer(rrsig_ksk)
                reply.header.rcode=getattr(RCODE,'NOERROR')

            elif domain==self.target:
                rr_ns=RR(rname=qname,rtype=2,ttl=self.ttl,rdata=NS('ns.'+self.target_nsdom))
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
    
def main(apex_zone):
    nameserver=RUCNSIP_Nameserver(apex_zone)
    
    dns_server=DNSServer(nameserver,port=53,address='0.0.0.0')
    for _ in range(nameserver.nameserver_threads):
        dns_server.start_thread()
    
    try:
        while True:
            time.sleep(600)
    except KeyboardInterrupt:
        sys.exit(0)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--apex_zone')
    args=parser.parse_args()

    main(args.apex_zone)