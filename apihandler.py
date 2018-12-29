import requests
import json
import argparse
import dbhandler
import vuln

VULDBKEY = ""
VULNERSKEY = ""
VULDBAPI = "https://vuldb.com/?api"



def parse_args():
    parser = argparse.ArgumentParser(description="test")
    parser.add_argument('query', help='The search query',nargs='?')
    parser.add_argument('-i',dest='id', help='Update the db',nargs='?')
    return parser.parse_args()

def parse_response(response):
    response = json.loads(response)
    if (response["response"]["status"] == "401"):
        print("Invalid API Key")
        return None
    elif (response["response"]["status"] == "200"):
        rl = list()
        for r in response["result"]:
            x = vuln.Vuln()
            x.vulDBbuild(r)
            dbhandler.write(x)
            rl.append(x)
        ##Returns a list of vuln objects
        return rl
    else:
        print ("Unknown API response")
        return None


#VULDB search
def search(query):
    rdata = {"apikey":VULDBKEY,"search":query}
    r = requests.post(VULDBAPI, data=rdata)
    return parse_response(r.text)

#Retrieve details of a specific vuln
def get_vuln(id):
    ##SEARCH the database first
    v =  dbhandler.get_vuln_byID(id)
    if v is not None:
        #Return the database result
        return v

    rdata = {"apikey":VULDBKEY,"id":id}
    r = requests.post(VULDBAPI,data=rdata)
    return parse_response(r.text)

#Get API keys
def getKeys():
    with open('keys.json') as keys:
        global VULDBKEY, VULNERSKEY
        d = json.load(keys)
        VULDBKEY = d['keys']['vuldb']
        VULNERSKEY = d['keys']['vulners']
    return
getKeys()

def main():
    args = parse_args()
    print (args)

    #If a specific vuln is requested use get_vuln
    if (args.id == None):
        vuln_list = search(args.query)
        for v in vuln_list:
            print (v)
    else:
        vuln_list = get_vuln(args.id)
        for v in vuln_list:
            print(v)




if __name__ == "__main__":
    main()