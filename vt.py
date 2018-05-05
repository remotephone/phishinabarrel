import requests
import json
import sys
import time

vt_base = 'https://www.virustotal.com/vtapi/v2/'
vtscan = vt_base + 'url/scan'
vtreport = vt_base + 'url/report'

def virus_total(vtkey, target_url):
    if vtkey == "":
        print("You need a VirusTotal API key to proceed. Check your config")
        sys.exit([1])
    else:
        print('[+] Checking Virustotal URL reputation...')
        vt_req_params = {'apikey': vtkey, 'url': target_url}
        vt_req_resp = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=vt_req_params)
        vt_json_req_resp = vt_req_resp.json()
        print(vtscan)
        if vt_json_req_resp['response_code'] == '1':
            print("Success... give me a second...")
            time.sleep(5)
            vt_resp_params =  {'apikey': vtkey, 'resource': target_url}
            vt_resp_results = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=vt_resp_params)
            print(vt_resp_results['scans'])
        else:
            print(vt_json_req_resp['verbose_msg'])