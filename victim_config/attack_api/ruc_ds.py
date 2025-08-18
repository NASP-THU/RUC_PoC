import sys
import json
import time
import datetime
import binascii
import argparse
from api import BASE_FOLDER
from dnslib import *
from dnslib.server import *

APEX='dnssec-ruc.xyz.'
TARGET='victim-rucds.'+APEX
PREFIX='sub'
NAMESERVER_THREADS=1000

class NSNameserver:
    def __init__(self,with_sig):
        self.with_sig=with_sig

        with open(f'{BASE_FOLDER}/config.json') as f:
            config_dict=json.load(f)
        self.timestamp=config_dict[TARGET]['TIMESTAMP']
        self.nsip=config_dict[TARGET]['NSIP']
        self.good_ttl=config_dict[TARGET]['GOOD_TTL']
        self.bad_ttl=config_dict[TARGET]['BAD_TTL']
        self.sig_inc_time=config_dict[TARGET]['SIGTIME']['SIG_INC']
        self.sig_exp_time=config_dict[TARGET]['SIGTIME']['SIG_EXP']

        self.rrsig_zsk_apex=config_dict[TARGET]['ZSK']['RRSIG']
        self.rrsig_ksk_apex=config_dict[TARGET]['KSK']['RRSIG']
        self.zsk_apex=config_dict[TARGET]['ZSK']['KEY']
        self.ksk_apex=config_dict[TARGET]['KSK']['KEY']
        self.tag_zsk_apex=config_dict[TARGET]['ZSK']['TAG']
        self.tag_ksk_apex=config_dict[TARGET]['KSK']['TAG']
        self.alg_zsk_apex=config_dict[TARGET]['ZSK']['ALG']
        self.alg_ksk_apex=config_dict[TARGET]['KSK']['ALG']

        self.sub_ds_digest=config_dict[TARGET]['SUB_DS']['DIGEST']
        self.sub_ds_tag=config_dict[TARGET]['SUB_DS']['TAG']
        self.sub_ds_alg=config_dict[TARGET]['SUB_DS']['ALG']
        self.sub_ds_hash=config_dict[TARGET]['SUB_DS']['HASH']
        self.sub_ds_rrsig=config_dict[TARGET]['SUB_DS']['RRSIG']

    def resolve(self,request,handler):
        reply=request.reply()
        qname=str(request.q.qname)
        qtype=int(str(request.q.qtype))
        try:
            domain=qname.lower()
            if domain.endswith(PREFIX+'.'+TARGET):
                rr_ds=RR(rname=PREFIX+'.'+TARGET,rtype=43,ttl=self.bad_ttl,rdata=DS(self.sub_ds_tag,algorithm=self.sub_ds_alg,digest_type=self.sub_ds_hash,digest=binascii.unhexlify(self.sub_ds_digest)))
                reply.add_answer(rr_ds)
                if self.with_sig==1:
                    # mute the last bit of DS's RRSIG
                    original_bytes=base64.b64decode(self.sub_ds_rrsig)
                    mutable_data=bytearray(original_bytes)
                    mutable_data[-1]=(mutable_data[-1] & 0b11111110) | 0b00000001
                    modified_data=bytes(mutable_data)
                    rrsig_ds=RR(rname=PREFIX+'.'+TARGET,rtype=46,ttl=self.bad_ttl,rdata=RRSIG(covered=43,algorithm=self.alg_zsk_apex,labels=4,orig_ttl=self.bad_ttl,
                                                                                        sig_exp=self.sig_exp_time,
                                                                                        sig_inc=self.sig_inc_time,
                                                                                        key_tag=self.tag_zsk_apex,
                                                                                        name=TARGET,
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

def main(config):
    nameserver=NSNameserver(config)
    
    dns_server=DNSServer(nameserver,port=53,address='0.0.0.0')
    for _ in range(NAMESERVER_THREADS):
        dns_server.start_thread()
    
    try:
        while True:
            time.sleep(600)
    except KeyboardInterrupt:
        sys.exit(0)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--with_sig')    # 0 for w/o SIG, 1 for w/ SIG
    args=parser.parse_args()
    
    main(int(args.with_sig))