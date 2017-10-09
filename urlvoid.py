import yaml
from xml.etree import ElementTree
import requests
from sys import argv


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

netcraft()