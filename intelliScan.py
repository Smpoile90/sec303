import argparse
import scanner
import dbhandler
import json
import vuln
from TIfeeds import vulDB, vulnershdlr


# Parse args using argparse
def parse_args():
    parser = argparse.ArgumentParser(description="Intelliscan threat intelligence integrated vulnerability scanner")
    parser.add_argument('host', help='The hostname, IP address or range to scan')
    parser.add_argument('-p', dest='ports', help='The port (comma separated list) or range of ports to be scanned',
                        nargs='?')
    parser.add_argument('-d', dest='dumb', help='Disable threat intelligence', action='store_true')
    parser.add_argument('-fA', dest='forceALL', help="Force use of all threat intelligence sources",
                        action='store_true')
    parser.add_argument('-oJ', dest="FILE", help="Output results in JSON to FILE")
    return parser.parse_args()


def queryTI(query):
    x = vulnershdlr.search(query)
    svvulnList = []
    for v in x:
        if v['bulletinFamily'] == "software":
            vul = vuln.Vuln()
            vul.vulnersBuild(v)
            dbhandler.write(vul)
            svvulnList.append(vul)
    return svvulnList


def outputResults(file, data):
    with open(file, 'w') as f:
        json.dump(data, f)


def customTest():
    # TODO
    pass


def main():
    # Parse arguments
    args = parse_args()

    # Conduct Scan
    if (args.host is not None):
        if args.ports is not None:
            scan = scanner.scan(args.host, args.ports)
        else:
            scan = scanner.scan(args.host)
    else:
        print("Please enter a valid IP")
        return

    ##Begin searching for vulnerabilities
    # Search caches DB
    scan = scan['scan']

    # ResultDict contains a dict of lists, port number+ service is the key and list of vulns is the value
    resultDict = {}
    for hkey, host in scan.items():
        for pkey, port in host['tcp'].items():
            svname = port['product'] + " " + port["version"]
            if (args.dumb is True):
                # Dont query TI
                # TODO
                pass
            else:
                # Do query TI
                id = str(hkey) + "_" + str(pkey) + "_" + svname
                resultDict[id] = queryTI(svname)
                # Do query explicit tests
                tests = dbhandler.getTests(str(pkey), port['name'])
                for t in tests:
                    d = {}
                    exec(t[3])
                    test = locals()['test']
                    test(hkey, pkey)

    ##Clean results wihtout vulnerabilties
    dlist = []
    for k, v in resultDict.items():
        if len(v) == 0:
            dlist.append(k)

    for key in dlist:
        del resultDict[key]

    if args.FILE is not None:
        for k, v in resultDict.items():
            for vuln in v:
                resultDict[k] = str(vuln)

        outputResults(args.FILE, resultDict)
    else:
        # output to stdout
        for k, v in resultDict.items():
            print("Host_Port_Service: " + k)
            for vuln in v:
                print(str(vuln) + "\n")


if __name__ == "__main__":
    main()
