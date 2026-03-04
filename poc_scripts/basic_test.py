import os
import json
import time
import argparse
from pathlib import Path

from utils import *

class BasicTest:
    def __init__(self,resolver_ip):
        self.resolver_ip=resolver_ip
        if self.resolver_ip!='127.0.0.1':
            self.resolver_os='windows'
        else:
            self.resolver_os='linux'

        with open(Path(os.getcwd()) / 'config.json') as f:
            config_dict=json.load(f)
        self.test_domain=config_dict['subdomains']['test']+'.'+config_dict['victim_apex'][self.resolver_os]
        
        self.basic_test_interval=config_dict['basic_test']['interval']
        self.basic_test_round=config_dict['basic_test']['round']
        self.basic_test_log_dir=config_dict['basic_test_log_dir']

    def query_test_domain(self):
        content=''
        
        # retry multiple times to avoid accidental response failures due to the cold start of the resolver cache
        for i in range(self.basic_test_round):
            dns_output=str(send_dns_request(self.resolver_ip,self.test_domain,'A',0,0,1,1))
            content+=dns_output
            print(dns_output)
            time.sleep(self.basic_test_interval)

        return ('10.0.0.0' in content) and ('flags: qr rd ra ad;' in content)
        
def test(resolver_ip):
    basic_test=BasicTest(resolver_ip)
    success=basic_test.query_test_domain()
    resolver=get_resolver(resolver_ip)

    if not os.path.exists(basic_test.basic_test_log_dir):
        os.makedirs(basic_test.basic_test_log_dir)
    if resolver_ip!='127.0.0.1':
        basic_test_log_file=Path(basic_test.basic_test_log_dir) / 'log_basic_test.csv'
    else:
        basic_test_log_file=Path(basic_test.basic_test_log_dir) / 'log_basic_test-microsoft.csv'
    fw=open(basic_test_log_file,'a')
    if success:
        print(f'[*] Resolver {resolver} tested, succeed.')
        fw.write(f'[*] Resolver {resolver} tested, succeed.\n')
    else:
        print(f'[*] Resolver {resolver} tested, failed.')
        fw.write(f'[*] Resolver {resolver} tested, failed.\n')
    fw.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--resolver_ip',help='IP address of the tested DNS resolver.',required=True)
    args=parser.parse_args()
    
    test(args.resolver_ip)
