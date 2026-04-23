import sys
import json
import time
import argparse
import datetime
from dnslib import *
from dnslib.server import *

class RUCEDNS0_Nameserver:
    def __init__(self,apex_zone):
        with open(f'config_subdomains.json') as f:
            config_dict=json.load(f)

        self.target=config_dict['subdomains']['ruc_edns0']+'.'+apex_zone+'.'
        self.apex_zone=apex_zone+'.'

        self.timestamp=config_dict[self.target]['TIMESTAMP']
        self.nsip=config_dict[self.target]['NSIP']
        self.ttl=config_dict[self.target]['TTL']
        self.ttl_nx=600
        self.sig_inc_time=config_dict[self.target]['SIGTIME']['SIG_INC']
        self.sig_exp_time=config_dict[self.target]['SIGTIME']['SIG_EXP']
        self.rrsig_soa=config_dict[self.target]['RRSIG_SOA']
        self.rrsig_nsec=config_dict[self.target]['RRSIG_NSEC']
        self.rrsig_zsk=config_dict[self.target]['ZSK']['RRSIG']
        self.rrsig_ksk=config_dict[self.target]['KSK']['RRSIG']
        self.zsk=config_dict[self.target]['ZSK']['KEY']
        self.ksk=config_dict[self.target]['KSK']['KEY']
        self.tag_zsk=config_dict[self.target]['ZSK']['TAG']
        self.tag_ksk=config_dict[self.target]['KSK']['TAG']
        self.alg_zsk=config_dict[self.target]['ZSK']['ALG']
        self.alg_ksk=config_dict[self.target]['KSK']['ALG']

        self.nameserver_threads=config_dict['nameserver_threads']
        
    def resolve(self,request,handler):
        reply=request.reply()
        qname=str(request.q.qname)
        qtype=int(str(request.q.qtype))
        src_ip=handler.client_address[0]
        try:
            domain=qname.lower()
            if domain.endswith(self.target):
                if qtype==48:
                    zsk_rr=RR(rname=qname,rtype=48,ttl=self.ttl,rdata=DNSKEY(flags=256,protocol=3,algorithm=8,key=base64.b64decode(self.zsk)))
                    ksk_rr=RR(rname=qname,rtype=48,ttl=self.ttl,rdata=DNSKEY(flags=257,protocol=3,algorithm=8,key=base64.b64decode(self.ksk)))
                    rrsig_ksk=RR(rname=qname,rtype=46,ttl=self.ttl,rdata=RRSIG(covered=48,algorithm=self.alg_ksk,labels=3,orig_ttl=self.ttl,
                                                                                    sig_exp=self.sig_exp_time,
                                                                                    sig_inc=self.sig_inc_time,
                                                                                    key_tag=self.tag_ksk,
                                                                                    name=self.target,
                                                                                    sig=base64.b64decode(self.rrsig_ksk)))
                    reply.add_answer(zsk_rr)
                    reply.add_answer(ksk_rr)
                    reply.add_answer(rrsig_ksk)

                    opt_record=EDNS0(flags='do',udp_len=4096)
                    reply.add_ar(opt_record)
                    reply.header.rcode=getattr(RCODE,'NOERROR')

                else:
                    rr_soa=RR(rname=self.target,rtype=6,ttl=self.ttl_nx,rdata=SOA("ns.rucedns0."+self.apex_zone,"admin."+self.apex_zone,(2025030601,3600,1800,1209600,600)))
                    rrsig_soa=RR(rname=self.target,rtype=46,ttl=self.ttl_nx,rdata=RRSIG(covered=6,algorithm=self.alg_zsk,labels=3,orig_ttl=self.ttl,
                                                                                    sig_exp=self.sig_exp_time,
                                                                                    sig_inc=self.sig_inc_time,
                                                                                    key_tag=self.tag_zsk,
                                                                                    name=self.target,
                                                                                    sig=base64.b64decode(self.rrsig_soa)))
                    rr_nsec=RR(rname=self.target,rtype=47,ttl=self.ttl_nx,rdata=NSEC(label=self.target,rrlist=['A','NS','SOA','RRSIG','NSEC','DNSKEY']))
                    rrsig_nsec=RR(rname=self.target,rtype=46,ttl=self.ttl_nx,rdata=RRSIG(covered=47,algorithm=self.alg_zsk,labels=3,orig_ttl=self.ttl_nx,
                                                                                    sig_exp=self.sig_exp_time,
                                                                                    sig_inc=self.sig_inc_time,
                                                                                    key_tag=self.tag_zsk,
                                                                                    name=self.target,
                                                                                    sig=base64.b64decode(self.rrsig_nsec)))
                    reply.add_auth(rr_soa)
                    reply.add_auth(rrsig_soa)
                    reply.add_auth(rr_nsec)
                    reply.add_auth(rrsig_nsec)
                    
                    # Remove EDNS0 OPT record in the additional section of the DNS response
                    # opt_record=EDNS0(flags='do',udp_len=4096)
                    # reply.add_ar(opt_record)

                    # To align with the "additional count" in the response header, add an arbitrary glue record
                    rr_a=RR(rname='ns.'+self.target,rtype=1,ttl=self.ttl,rdata=A(self.nsip))
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
    
def main(apex_zone):
    nameserver=RUCEDNS0_Nameserver(apex_zone)
    
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