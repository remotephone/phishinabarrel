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
import yaml
from xml.etree import ElementTree


"""
def main():

    # Ask user for URL and reason for submitting it to netcraft.
    # To see their form, go to http://toolbar.netcraft.com/report_url
    prompt = "> "
    print "What URL do you want to report? Include the protocol (http[s]://)"
    check_url = raw_input(prompt)
    print "Why are you reporting this URL - keep it to one word"
    check_reason = raw_input(prompt)
    print get_config(cfg['netcraft']['nc_name'])
"""

# Pull the config from config.yaml. This file includes API keys and form
# fields.
with open("config.yaml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile)

# Ask user for URL and reason for submitting it to netcraft.
# To see their form, go to http://toolbar.netcraft.com/report_url
prompt = "> "
print "What URL do you want to report? Include the protocol (http[s]://)"
check_url = raw_input(prompt)
print "Why are you reporting this URL - keep it to one word"
check_reason = raw_input(prompt)



# This part will check the URL against VirusTotal. Make sure you have your API
# key in the config.yaml file for this to work. 

def virus_total():

# Make sure the user wants to check URL first, give options to skip and report.

    vt_decision = "yes/no/what: "
    vt_ask =  "Do you want to check VirusTotal for the URL reputation?"
    print vt_ask
    vt_choice = raw_input(vt_decision)
    if vt_choice.lower() == 'yes':

# Inform the user and query Virus Total

        print '[+] Checking Virustotal URL reputation...'
        vt_params = {'apikey': cfg['virustotal']['vt_apikey'], 'url': check_url}
        vt_response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=vt_params)
        vt_json_response = vt_response.json()

# Handle No, where the user knows what to do

    elif vt_choice.lower() == 'no':
        print "Do you want to just report the url?"
        vt_justrpt = raw_input(vt_decision)

        if vt_justrpt.lower() == 'yes':
            # This will direct the user to report functions
            # Currently in the netcraft() function
            netcraft()

        else:
            print 'Alright, goodbye!'

    else:
        vt_checktwice = "Did you accidentally run this?"
        print vt_checktwice
        



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

        payload = {'name': cfg['netcraft']['nc_name'], 'email': cfg['netcraft']['nc_email'], 'url': check_url, 'reason': check_reason}
        r = requests.post(netcraft_url, payload)


        # If we had a successful post, then print the result. If not, I need to
        # write error handling.
        if self.response.status_code == requests.codes.ok:
            print 'Success! Here is what you got:'
            print r.text
            safebrowse()

        else:
            print 'Maybe netcraft is down... skipping...'
            safebrowse()


    elif netcraft_phishing == "no":
        print 'Skipping netcraft submission'
        print '\n'
        safebrowse()

    elif netcraft_phishing == "what":
        print 'Netcraft doesn\'t want you submitting just anything. Make sure'\
            ' it meets their definition'
        print '\n'
        netcraft()

    else:
        print 'I need yes, no, or what please.'
        print '\n'
        netcraft()

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

netcraft()

"""


def netcraft():
    # Ask user for URL and reason for submitting it to netcraft.
    # To see their form, go to http://toolbar.netcraft.com/report_url
    prompt = "> "
    print "What URL do you want to report? Include the protocol (http[s]://)"
    check_url = raw_input(prompt)
    print "Why are you reporting this URL - keep it to one word"
    check_reason = raw_input(prompt)

    # Pull the config from config.yaml. This file includes API keys and form
    # fields.
    with open("config.yaml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile)


    # Submit the issue to netcraft.
    url = "http://toolbar.netcraft.com/report_url"
    # Construct your payload. This pulls the value from the netcraft section
    # and nc_name and nc_email keys. It also pulls the values you submitted
    # when prompted above.
    payload = {'name': cfg['netcraft']['nc_name'], 'email': cfg['netcraft']['nc_email'], 'url': check_url, 'reason': check_reason}
    r = requests.post(url, payload)

    # If we had a successful post, then print the result. If not, I need to
    # write error handling.
    if self.response.status_code == requests.codes.ok:
        print r.text

if __name__ == "__main__":
    main()

"""
