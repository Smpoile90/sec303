import requests
import json
import argparse
import nmap
import apihandler

#Parse args using argparse
def parse_args():
    parser = argparse.ArgumentParser(description="test")
    parser.add_argument('ips', help='The Host or Range to Scan')
    parser.add_argument('-p',dest='ports', help='The ports to be scanned',nargs='?')
    return parser.parse_args()



def scan(ips):
    print (type(ips))
    scanner = nmap.PortScanner()
    return scanner.scan(ips)

def main():
    #Parse arguments
    args = parse_args()
    print (args)
    #result = scan(args.ips)

    print (x)










if __name__ == "__main__":
    main()