# This is a work in progress and I obviously don't know what I'm doing, so
# don't use this. 

"""
Things to do more:
- Figure out what good formatting is
- Does the order of this stuff matter?
- Add comments
- Check all variable prefixes (nc for netcraft, vt VirusTotal, etc)
- test?
- Figure out if and how to main()
"""

import argparse
import time
import sys
from xml.etree import ElementTree

import requests
import json

from config import cfg
from vt import VirusTotal as vt
import sb

# Pull the config from config.yaml. This file includes API keys and form
# fields.

# Parse any command line arguments, if none ask user for URL.
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest='check_url', help='This is the URL \
            you will evaluate.')
    parser.add_argument("-w", "--why", default='phishing', help='This flag is used to give \
            Google Safe Browsing a different reason other than phishing (malware?).')
    parser.add_argument("-r", "--reputation", dest='repcheck',
            action='store_true', help='This will check VirusTotal for the reputation\
            of the URL. You need an api key in the config.yaml file.')
    parser.add_argument("-e", "--easy", dest='easymode', action='store_true',\
            help="Easy mode - report only to services that don\'t require manual \
            interaction")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    else:
        args = parser.parse_args()
    return args



def main():
    args = parse_args()
    VTKEY = cfg.get('vt_apikey')
    TARGET_URL = args.check_url
    check_reason = args.why

    vtcheck = vt(VTKEY, TARGET_URL)
    report = vtcheck.get_urlvt()
    positives = []
    if report['response_code'] == 1:
        for x in sorted(report.get('scans')):
            if report['scans'][x].get('detected'):
                positives.append([x,
                            'True',
                            report['scans'][x]['result'] if report['scans'][x]['result'] else ' -- ',
                            report['scans'][x]['version'] if  'version' in report['scans'][x] and report['scans'][x]['version'] else ' -- ',
                            report['scans'][x]['update'] if 'update' in report['scans'][x] and report['scans'][x]['update'] else ' -- '
                            ])
        print(positives)
    elif report['response_code'] == -2:
        time.sleep(15)
        report = vtcheck.get_urlvt()
        print(json.dumps(report, sort_keys=False, indent=4))
    elif report['response_code'] == 0:
        print('not there, putting')
        vtcheck.put_urlvt()
        time.sleep(15)
        report = vtcheck.get_urlvt()
        print(json.dumps(report, sort_keys=False, indent=4))


    print('[+] Google Safebrowsing')

    sb.safebrowse(TARGET_URL, check_reason)




if __name__ == "__main__":
    main()

