import os
from sys import argv
import requests
import yaml

# import the config file.
with open("myconfig.yaml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile)

print cfg['urlscan.io']

"""
headers = {'Content-Type': 'application/json','API-Key': $apikey}
payload = {'url': sys.argv[1],'public': 'on'}

r = requests.post("https://urlscan.io/api/v1/scan/", data=payload, headers=headers)
return r
"""
