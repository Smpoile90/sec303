import argparse
import scanner
from TIfeeds import *

#Parse args using argparse
def parse_args():
    parser = argparse.ArgumentParser(description="""Intelliscan threat intelligence integrated vulnerability scanner""")
    parser.add_argument('host', help='The hostname, IP address or range to scan')
    parser.add_argument('-p',dest='ports', help='The port (comma separated list) or range of ports to be scanned',nargs='?')
    parser.add_argument('-d', dest='dumb', help='Disable threat intelligence',action='store_true')
    return parser.parse_args()

def main():
    #Parse arguments
    args = parse_args()
    print(args.host)

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

    #result = scan(args.host)











if __name__ == "__main__":
    main()