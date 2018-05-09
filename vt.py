import requests
import json
import sys
import time
from pp_json import pp_json


class VirusTotal():
    def __init__(self, vtkey, target_url):
        """Creat a virustotal request or pull a report"""
        self.vtkey = vtkey
        self.target_url = target_url
        self.vt_scan = 'https://www.virustotal.com/vtapi/v2/url/scan' 
        self.vt_rprt = 'https://www.virustotal.com/vtapi/v2/url/report'
        self.vt_params =  {'apikey': self.vtkey, 'resource': self.target_url}
        self.headers = {
                        "Accept-Encoding": "gzip, deflate",
                        "User-Agent" : "phishinabarrel - https://github.com/remotephone/phishinabarrel"
                        }


    def put_vt(self):
        r = requests.post(self.vt_scan, params=self.vt_params)
        json_resp = r.json()
        return json_resp
        #putjson = pp_json(json_resp)
        #print(pretty_json)
        #return putjson


    def get_vt(self):
        r = requests.post(self.vt_rprt, params=self.vt_params)
        json_resp = r.json()
        return json_resp

    def return_rprt(self):
        r = requests.post(self.vt_rprt, params=self.vt_params)
        json_resp = r.json()
        positives = json_resp['positives']
        results_url = json_resp['permalink']
        return positives, results_url
        print(str(positives) + " positive matches found. \nSee " + results_url + '\n')
        #getjson = pp_json(json_resp)
        #print(pretty_json) 
        #return getjson

# vt_base = 'https://www.virustotal.com/vtapi/v2/'
# vtscan = vt_base + 'url/scan'
# vtreport = vt_base + 'url/report'
# headers = {
#   "Accept-Encoding": "gzip, deflate",
#   "User-Agent" : "phishinabarrel - https://github.com/remotephone/phishinabarrel"
#   }

#     if vtkey == "":
#         print("You need a VirusTotal API key to proceed. Check your config")
#         sys.exit([1])
#     else:
#         try:
#             vt_resp_params =  {'apikey': vtkey, 'resource': target_url}
#             vt_resp_results = requests.get(vtreport, data=vt_resp_params)
#             print(vt_resp_results['scans'])
#         except: 
#             print('[+] Checking Virustotal URL reputation...')
#             vt_req_params = {'apikey': vtkey, 'url': target_url}
#             vt_req_resp = requests.post(vtscan, data=vt_req_params)
#             vt_json_req_resp = vt_req_resp.json()
#             print(vtscan)
#             print(vt_json_req_resp['response_code'])
#             if vt_json_req_resp['response_code'] == '1':
#                 print("Success... give me a second...")
#                 time.sleep(5)
#                 vt_resp_params =  {'apikey': vtkey, 'resource': target_url}
#                 vt_resp_results = requests.get(vtreport, data=vt_resp_params)
#                 print(vt_resp_results['scans'])
#             else:
#                 print(vt_json_req_resp['verbose_msg'])