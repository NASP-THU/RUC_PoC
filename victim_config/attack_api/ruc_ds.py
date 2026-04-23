import sys
import json
import time
import argparse
import binascii
import datetime
from dnslib import *
from dnslib.server import *

class RUCDS_Nameserver:
    def __init__(self,apex_zone,with_sig):
        with open('config_subdomains.json') as f:
            config_dict=json.load(f)

        self.target=config_dict['subdomains']['ruc_ds']+'.'+apex_zone+'.'
        self.target_apex=config_dict['subdomains']['ruc_ds_apex']+'.'+apex_zone+'.'
        self.with_sig=with_sig

        self.timestamp=config_dict[self.target_apex]['TIMESTAMP']
        self.nsip=config_dict[self.target_apex]['NSIP']
        self.ttl=config_dict[self.target_apex]['TTL']
        self.sig_inc_time=config_dict[self.target_apex]['SIGTIME']['SIG_INC']
        self.sig_exp_time=config_dict[self.target_apex]['SIGTIME']['SIG_EXP']

        self.rrsig_zsk_apex=config_dict[self.target_apex]['ZSK']['RRSIG']
        self.rrsig_ksk_apex=config_dict[self.target_apex]['KSK']['RRSIG']
        self.zsk_apex=config_dict[self.target_apex]['ZSK']['KEY']
        self.ksk_apex=config_dict[self.target_apex]['KSK']['KEY']
        self.tag_zsk_apex=config_dict[self.target_apex]['ZSK']['TAG']
        self.tag_ksk_apex=config_dict[self.target_apex]['KSK']['TAG']
        self.alg_zsk_apex=config_dict[self.target_apex]['ZSK']['ALG']
        self.alg_ksk_apex=config_dict[self.target_apex]['KSK']['ALG']

        self.sub_ds_digest=config_dict[self.target_apex]['SUB_DS']['DIGEST']
        self.sub_ds_tag=config_dict[self.target_apex]['SUB_DS']['TAG']
        self.sub_ds_alg=config_dict[self.target_apex]['SUB_DS']['ALG']
        self.sub_ds_hash=config_dict[self.target_apex]['SUB_DS']['HASH']
        self.sub_ds_rrsig=config_dict[self.target_apex]['SUB_DS']['RRSIG']

        self.nameserver_threads=config_dict['nameserver_threads']

    def resolve(self,request,handler):
        reply=request.reply()
        qname=str(request.q.qname)
        qtype=int(str(request.q.qtype))
        try:
            domain=qname.lower()
            if domain.endswith(self.target):
                rr_ds=RR(rname=self.target,rtype=43,ttl=self.ttl,rdata=DS(self.sub_ds_tag,algorithm=self.sub_ds_alg,digest_type=self.sub_ds_hash,digest=binascii.unhexlify(self.sub_ds_digest)))
                reply.add_answer(rr_ds)
                if self.with_sig==1:
                    # mutate the last bit of DS's RRSIG
                    original_bytes=base64.b64decode(self.sub_ds_rrsig)
                    mutable_data=bytearray(original_bytes)
                    mutable_data[-1]=mutable_data[-1] ^ 0b00000001
                    modified_data=bytes(mutable_data)
                    rrsig_ds=RR(rname=self.target,rtype=46,ttl=self.ttl,rdata=RRSIG(covered=43,algorithm=self.alg_zsk_apex,labels=4,orig_ttl=self.ttl,
                                                                                        sig_exp=self.sig_exp_time,
                                                                                        sig_inc=self.sig_inc_time,
                                                                                        key_tag=self.tag_zsk_apex,
                                                                                        name=self.target_apex,
                                                                                        sig=modified_data))
                    reply.add_answer(rrsig_ds)

                reply.header.rcode=getattr(RCODE,'NOERROR')
                print(datetime.datetime.today(),domain,'DS sent.')

            else:
                # print('not match:',qname)
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

def main(apex_zone,with_sig):
    nameserver=RUCDS_Nameserver(apex_zone,with_sig)
    
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
    parser.add_argument('--with_sig')    # 0 for w/o SIG, 1 for w/ SIG
    args=parser.parse_args()
    
    main(args.apex_zone,int(args.with_sig))