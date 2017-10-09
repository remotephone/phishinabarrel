# This is a work in progress and I obviously don't know what I'm doing, so
# don't use this. 
import requests
from sys import argv
import yaml
from xml.etree import ElementTree

def main():

    # Ask user for URL and reason for submitting it to netcraft.
    # To see their form, go to http://toolbar.netcraft.com/report_url
    prompt = "> "
    print "What URL do you want to report? Include the protocol (http[s]://)"
    check_url = raw_input(prompt)
    print "Why are you reporting this URL - keep it to one word"
    check_reason = raw_input(prompt)
    print get_config(cfg['netcraft']['nc_name'])

def get_config():
    # Pull the config from config.yaml. This file includes API keys and form
    # fields.
    with open("config.yaml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile)




"""

class CheckUrlReputation():


def safebrowse():
    # Ask user for URL and reason for submitting it to netcraft.
    # To see their form, go to http://toolbar.netcraft.com/report_url
    print 'Click the URL below, it should autopopulate the fields. Complete '\
        'the captcha and submit to report the site to Google Safe Browsing.'
    print 'https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en&url=' + check_url



def netcraft():


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
"""

if __name__ == "__main__":
    main()
