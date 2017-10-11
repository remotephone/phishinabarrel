# This is a work in progress and I obviously don't know what I'm doing, so
# don't use this. 
import requests
from sys import argv
import yaml
from xml.etree import ElementTree
import urllib


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


"""

def safebrowse():
    # This will submit the URL to Google Safe browsing. Since they have Captcha
    # protection on the page, you'll need to manually visit this URL. It should
    # autopopulate what it can through the url.
    enc_url = urllib.pathname2url(check_url)
    enc_reason = urllib.pathname2url(check_reason)
    print 'Click the URL below, it should autopopulate the fields. Complete '\
        'the captcha and submit to report the site to Google Safe Browsing.'
    print 'https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en&url=' + enc_url + '&dq=' + enc_reason
"""



def netcraft():


# Check if phishing - they're pretty specific on what they ask for
    print """
    Is this a phishing url? Is it "one that is attempting to impersonate a
    site operated by an organisation with which the victim of the phishing
    attempt has an existing relationship, in order to obtain passwords or other
    personal information for use in some type of fraud?"
    """
    prompt_nc = "yes/no/what: "
    netcraft_phishing = raw_input(prompt_nc)
    if netcraft_phishing == "yes":

        # Keep the user informed
        print '[+] Submitting request to Netcraft'

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
            print r.text
            safebrowse()
        else:
            print 'Maybe netcraft is down... skipping...'
            safebrowse()


    elif netcraft_phishing == "no":
        print 'Skipping netcraft submission'
        safebrowse()

    elif netcraft_phishing == "what":
        print 'Netcraft doesn\'t want you submitting just anything. Make sure'\
            ' it meets their definition'
        netcraft()

    else:
        print 'I need yes, no, or what please.'


def safebrowse():
    # This will submit the URL to Google Safe browsing. Since they have Captcha
    # protection on the page, you'll need to manually visit this URL. It should
    # autopopulate what it can through the url.
    enc_url = urllib.pathname2url(check_url)
    enc_reason = urllib.pathname2url(check_reason)
    print 'Click the URL below, it should autopopulate the fields. Complete '\
        'the captcha and submit to report the site to Google Safe Browsing.'
    print 'https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en&url=' + enc_url + '&dq=' + enc_reason


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
