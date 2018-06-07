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
        self.urlbase = 'https://www.virustotal.com/vtapi/v2/'
        # self.vt_scan = 'https://www.virustotal.com/vtapi/v2/url/scan' 
        # self.vt_rprt = 'https://www.virustotal.com/vtapi/v2/url/report'
        self.vt_urldata =  {'apikey': self.vtkey, 'resource': self.target_url}
        self.vt_scanparams =  {'apikey': self.vtkey, 'url': self.target_url}
        self.headers = {
                        #"Accept-Encoding": "gzip, deflate",
                        "User-Agent" : "phishinabarrel - https://github.com/remotephone/phishinabarrel"
                        }


    def put_urlvt(self):
        vturl = self.urlbase + 'url/scan'
        r = requests.post(vturl, data=self.vt_scanparams, headers=self.headers)
        response = r.json()
        return response


    def get_urlvt(self):
        vturl = self.urlbase + 'url/report'
        r = requests.get(vturl, params=self.vt_urldata, headers=self.headers)
        response = r.json()
        return response
