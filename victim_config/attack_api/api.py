import os
import sys
import json
import time
import argparse
import threading
from flask import Flask, request, jsonify
from flask_basicauth import BasicAuth

with open('config.json') as f:
    config_dict=json.load(f)

app = Flask(__name__)
attack_api_url=config_dict['attack_api']['url']
attack_api_port=config_dict['attack_api']['port']

@app.route(f'/{attack_api_url}', methods=['POST'])
def ruc_attack_api():
    apex_zone=app.config['APEX_ZONE']
    data = request.get_json()
    if 'attack' in data.keys():
        if data['attack']=='ruc_dnskey':
            ref,msg=ruc_dnskey_attack(apex_zone,data['mode'],data['with_sig'])
        elif data['attack']=='ruc_ds':
            ref,msg=ruc_ds_attack(apex_zone,data['mode'],data['with_sig'])
        elif data['attack']=='ruc_nsip':
            ref,msg=ruc_nsip_attack(apex_zone,data['mode'])
        elif data['attack']=='ruc_edns0':
            ref,msg=ruc_edns0_attack(apex_zone,data['mode'])
        else:
            ref=-1
            msg='Invalid request!'
    else:
        ref=-1
        msg='Invalid request!'
    return jsonify({'ref':ref,'msg':msg})

def ruc_attack_run(apex_zone,port):
    app.config['APEX_ZONE']=apex_zone
    app.run(host='0.0.0.0',port=port)

def kill_ruc_attacker():
    os.system(f'chmod +x kill_attacker.sh')
    return os.system(f'bash kill_attacker.sh')

def ruc_dnskey_attack(mode,with_sig):
    if mode=='resume':
        code1=kill_ruc_attacker()
        code2=os.system('service named start')
        if code1!=0:
            return 1,'fail to kill attacker script'
        if code2!=0:
            return 2,'fail to resume ADNS'
        else:
            return 0,'resume ADNS success'
    elif mode=='inject':
        code0=kill_ruc_attacker()
        code1=os.system('service named stop')
        code2=os.system(f'screen -dmS atk-ruc-dnskey python3 ruc_dnskey.py --with_sig '+str(with_sig))
        if code0!=0:
            return 1,'fail to kill attacker script'
        if code1!=0:
            return 3,'fail to stop ADNS'
        if code2!=0:
            return 4,'fail to run attacker script'
        return 0,'inject success'

def ruc_ds_attack(mode,with_sig):
    if mode=='resume':
        code1=kill_ruc_attacker()
        code2=os.system('service named start')
        if code1!=0:
            return 1,'fail to kill attacker script'
        if code2!=0:
            return 2,'fail to resume ADNS'
        else:
            return 0,'resume ADNS success'
    elif mode=='inject':
        code0=kill_ruc_attacker()
        code1=os.system('service named stop')
        code2=os.system(f'screen -dmS atk-ruc-ds python3 ruc_ds.py --with_sig '+str(with_sig))
        if code0!=0:
            return 1,'fail to kill attacker script'
        if code1!=0:
            return 3,'fail to stop ADNS'
        if code2!=0:
            return 4,'fail to run attacker script'
        return 0,'inject success'

def ruc_nsip_attack(mode):
    if mode=='resume':
        code1=kill_ruc_attacker()
        code2=os.system('service named start')
        if code1!=0:
            return 1,'fail to kill attacker script'
        if code2!=0:
            return 2,'fail to resume ADNS'
        else:
            return 0,'resume ADNS success'
    elif mode=='inject':
        code0=kill_ruc_attacker()
        code1=os.system('service named stop')
        code2=os.system(f'screen -dmS atk-ruc-nsip python3 ruc_nsip.py')
        if code0!=0:
            return 1,'fail to kill attacker script'
        if code1!=0:
            return 3,'fail to stop ADNS'
        if code2!=0:
            return 4,'fail to run attacker script'
        return 0,'inject success'
    
def ruc_edns0_attack(mode):
    if mode=='resume':
        code1=kill_ruc_attacker()
        code2=os.system('service named start')
        if code1!=0:
            return 1,'fail to kill attacker script'
        if code2!=0:
            return 2,'fail to resume ADNS'
        else:
            return 0,'resume ADNS success'
    elif mode=='inject':
        code0=kill_ruc_attacker()
        code1=os.system('service named stop')
        code2=os.system(f'screen -dmS atk-ruc-edns0 python3 ruc_edns0.py')
        if code0!=0:
            return 1,'fail to kill attacker script'
        if code1!=0:
            return 3,'fail to stop ADNS'
        if code2!=0:
            return 4,'fail to run attacker script'
        return 0,'inject success'
    
if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--apex_zone',required=True)
    args=parser.parse_args()

    thread = threading.Thread(target=ruc_attack_run,kwargs={'apex_zone':args.apex_zone,'port':attack_api_port})
    thread.daemon = True
    thread.start()
    try:
        while True:
            time.sleep(600)
    except KeyboardInterrupt:
        sys.exit(0)