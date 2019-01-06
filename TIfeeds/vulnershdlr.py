import json
import vulners
import vuln

VULNERSKEY = None
vulnersapi = vulners.Vulners()

#Get API keys
def getKeys():
    with open('keys.json') as keys:
        global  VULNERSKEY, vulnersapi
        d = json.load(keys)
        VULNERSKEY = d['keys']['vulners']

    vulnersapi = vulners.Vulners(api_key=VULNERSKEY)
    return

getKeys()

#VULDB search
def search(query):
    result = vulnersapi.search(query)
    return result

def search_name_version(name,version):
    result = vulnersapi.softwareVulnerabilities(name,version)
    return result

def get_vuln(id):
    result = vulnersapi.references(id)
    return result

