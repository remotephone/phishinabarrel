import requests
from sys import argv
import yaml


def function():
    # Ask user for URL and reason for submitting it to XXXXXXXXXXX
    prompt = "> "
    print "What URL do you want to report? Include the protocol (http[s]://)"
    check_url = raw_input(prompt)
# This might not be necessary depending on the tool, this is for forms.
    print "Why are you reporting this URL - keep it to one word"
    check_reason = raw_input(prompt)

    # Pull the config from config.yaml. This file includes API keys and form
    # fields.
    with open("config.yaml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile)


    # Submit the issue to netcraft.
    url = "http://"
    # Construct your payload for the post request.
    payload = {'API-INPUT1': cfg['SECTION']['KEY'], 'API-INPUT2': cfg['netcraft']['nc_email'], 'url': check_url, 'reason': check_reason}
    r = requests.post(url, payload)

    # If we had a successful post, then print the result. If not, I need to
    # write error handling.
    if self.response.status_code == requests.codes.ok:
        print r.text

netcraft()
