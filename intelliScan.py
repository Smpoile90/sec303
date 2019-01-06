import argparse
import scanner
from TIfeeds import vulDB,vulnershdlr

#Parse args using argparse
def parse_args():
    parser = argparse.ArgumentParser(description="Intelliscan threat intelligence integrated vulnerability scanner")
    parser.add_argument('host', help='The hostname, IP address or range to scan')
    parser.add_argument('-p',dest='ports', help='The port (comma separated list) or range of ports to be scanned',nargs='?')
    parser.add_argument('-d', dest='dumb', help='Disable threat intelligence',action='store_true')
    parser.add_argument('-fA', dest='forceALL', help="Force use of all threat intelligence sources",action='store_true')
    parser.add_argument('-oJ',dest="FILE", help="Output results in JSON to FILE",nargs='?')
    return parser.parse_args()

def queryTI():
    #TODO
    pass

def outputResults():
    #TODO
    pass

def main():
    #Parse arguments
    args = parse_args()
    print(args.host)

    ####DELETE AFTER USE
    #Conduct Scan
    if (args.host is not None):
        if args.ports is not None:
            scan = scanner.scan(args.host,args.ports)
        else:
            scan = scanner.scan(args.host)
    else:
        print ("Please enter a valid IP")
        return

    print (scan)

    ##Begin searching for vulnerabilities
    #Search caches DB
    scan = scan['scan']

    for hkey,host in scan.items():
        for pkey,port in host['tcp'].items():
            print(str(pkey)+ " " + port['product']+ " " + port["version"])

            if (args.dumb is True):
                #Dont query TI
                #TODO
                pass
            else:
                #Do query TI
                #TODO
                pass

if __name__ == "__main__":
    main()