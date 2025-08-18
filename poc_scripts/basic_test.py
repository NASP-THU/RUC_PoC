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
            self.test_domain='test.dnssec-ruc.xyz'
        else:
            self.test_domain='test.dnssec-ruc-ms.xyz'

    def query_test_domain(self):
        content=''
        for i in range(5):  # retry 5 times to avoid request timeout due to the potential cold start of DNS resolver
            dns_output=str(send_dns_request(self.resolver_ip,self.test_domain,'A',0,0,1,1))
            content+=dns_output
            print(dns_output)
            time.sleep(1)

        return ('10.0.0.0' in content) and ('flags: qr rd ra ad;' in content)
        
def test(resolver_ip):
    basic_test=BasicTest(resolver_ip)
    success=basic_test.query_test_domain()
    resolver=get_resolver(resolver_ip)

    BASIC_TEST_LOG_DIR='basic_test_result'
    if not os.path.exists(BASIC_TEST_LOG_DIR):
        os.makedirs(BASIC_TEST_LOG_DIR)
    if resolver_ip!='127.0.0.1':
        basic_test_log_file=Path(BASIC_TEST_LOG_DIR) / 'log_basic_test.csv'
    else:
        basic_test_log_file=Path(BASIC_TEST_LOG_DIR) / 'log_basic_test-microsoft.csv'
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
