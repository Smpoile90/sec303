import nmap
import requests
import threading
import progressbar
import time


ready = 0
sresult = None

def _scan(ips,*args):
    global ready,sresult
    try:
        scanner = nmap.PortScanner()
    except nmap.PortScannerError as e:
        print("Nmap is not working correctly" + str(e))
        ready = 1
        return
    if (len(args) is not 0):
        ports = args[0]
        sresult = scanner.scan(ips,ports)
        ready = 1
        return
    else:
        sresult = scanner.scan(ips)
        ready = 1
        return

def scan(ips,*args):
    global ready,sresult

    if (len(args) is 0):
        worker = threading.Thread(target=_scan, args=(ips,))
    else:
        worker = threading.Thread(target=_scan, args=(ips,args[0]))
    worker.start()
    bar = progressbar.ProgressBar(max_value=progressbar.UnknownLength)
    print ("Scan starting!!!")
    i = 0
    while ready is 0:
        time.sleep(0.1)
        i += 1
        bar.update(i)

    ready = 0
    worker.join()
    return sresult


