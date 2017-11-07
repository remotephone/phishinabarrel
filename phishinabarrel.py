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

# Requestor modules
import requests
import urllib

# Config and input handlers
from sys import argv
from xml.etree import ElementTree
import argparse
from config import cfg
import time



# Pull the config from config.yaml. This file includes API keys and form
# fields.

# Parse any command line arguments, if none ask user for URL.
url_parser = argparse.ArgumentParser()
url_parser.add_argument("-u", "--url", dest='check_url', help='This is the URL \
        you will evaluate. This is required.')
url_parser.add_argument("-r", "--reputation", dest='repcheck',
        action='store_true', help='This will check VirusTotal for the reputation\
        of the URL. You need an api key in the config.yaml file.')
url_parser.add_argument("-e", "--easy", dest='easymode', action='store_true', \
        help="Easy mode - report only to services that don\'t require manual \
        interaction")
args = url_parser.parse_args()
if (args.check_url == None):
    url_parser.print_help()

else:
    check_reason = "phishing"

"""
originally planned to prompt the user why - but if this is phishing
reporting only that might be redundant - taking someones advice and setting
this to phishing alert by default.

    print "Why are you reporting this URL - keep it to one word"
    prompt = "> "
    check_reason = raw_input(prompt)
"""

def virus_total():

# Make sure the user wants to check URL first, give options to skip and report.

    if args.repcheck == True:

# Inform the user and query Virus Total

        if cfg.get('vt_apikey') == "":
            print "You need a VirusTotal API key to proceed. Check your \
            config"
        else:
            print '[+] Checking Virustotal URL reputation...'
            vt_base = 'https://www.virustotal.com/vtapi/v2/'
            url_scan_endpt = vt_base + 'url/scan'
            url_rprt_endpt = vt_base + 'url/report'
            vt_req_params = {'apikey': cfg.get('vt_apikey'), 'url': args.check_url}
            print url_scan_endpt
            vt_req_resp = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', 
                    data=vt_req_params)
            vt_json_req_resp = vt_req_resp.json()
            if vt_json_req_resp['response_code'] == '1':
                print "Success... give me a second..."
                time.sleep(5)
                vt_resp_params =  {'apikey': cfg.get('vt_apikey'), 'resource':
                        args.check_url}
                vt_resp_results = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', 
                        data=vt_resp_params)
                print vt_resp_results['scans']
            else:
                print vt_json_req_resp['verbose_msg']

    else:
        print "[+] Reporting to NetCraft..."
        netcraft()



def netcraft():

    print '[+] Checking Netcraft submission...'
    print '\n'
# Check if phishing - they're pretty specific on what they ask for

    print """
    Is this a phishing url? Is it "one that is attempting to impersonate a
    site operated by an organisation with which the victim of the phishing
    attempt has an existing relationship, in order to obtain passwords or other
    personal information for use in some type of fraud?"
    """
    nc_prompt = "yes/no/what: "
    netcraft_phishing = raw_input(nc_prompt)


    if netcraft_phishing == "yes":

        # Keep the user informed
        print '[+] Submitting request to Netcraft'
        print '...'
        # Submit the issue to netcraft.
        netcraft_url = "http://toolbar.netcraft.com/report_url"

        # Construct your payload. This pulls the value from the netcraft section
        # and nc_name and nc_email keys. It also pulls the values you submitted
        # when prompted above.

        payload = {'name': cfg.get(nc_name), 'email': cfg.get(nc_email), 'url': check_url, 'reason': check_reason}
        r = requests.post(netcraft_url, payload)


        # If we had a successful post, then print the result. If not, I need to
        # write error handling.
        if self.response.status_code == requests.codes.ok:
            print 'Success! Here is what you got:'
            print r.text
            exit()
        else:
            print 'Maybe netcraft is down... skipping...'
            exit()

    elif netcraft_phishing == "no":
        print 'Skipping netcraft submission'
        print '\n'
        exit()

    elif netcraft_phishing == "what":
        print 'Netcraft doesn\'t want you submitting just anything. Make sure'\
            ' it meets their definition'
        print '\n'
        exit()

    else:
        print 'I need yes, no, or what please.'
        print '\n'
        exit()






def safebrowse():

    print '[+] Google Safebrowsing'
    print '\n'
    # This will submit the URL to Google Safe browsing. Since they have Captcha
    # protection on the page, you'll need to manually visit this URL. It should
    # autopopulate what it can through the url.
    enc_url = urllib.pathname2url(check_url)
    enc_reason = urllib.pathname2url(check_reason)
    print 'Click the URL below, it should autopopulate the fields. Complete '\
        'the captcha and submit to report the site to Google Safe Browsing.'
    print 'https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en&url=' + enc_url + '&dq=' + enc_reason
    print '\n'











def main():
# Can i make this a function taht just tries and moves on if i get a fail?
        virus_total()


if __name__ == "__main__":
    main()
