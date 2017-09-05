#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import Queue
import threading
import time
import sys
import socket
import optparse
from time import sleep

def ip2num(ip):
    ip = [int(x) for x in ip.split('.')]
    return ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3]
    
def num2ip(num):
    return '%s.%s.%s.%s' % ((num & 0xff000000) >> 24,(num & 0x00ff0000) >> 16,(num & 0x0000ff00) >> 8,num & 0x000000ff)


def ip_range(start, end):
    return [num2ip(num) for num in range(ip2num(start), ip2num(end) + 1) if num & 0xff]


def scan_open_port_server(done, queue, ports, lock):
    while True:
        host,port = queue.get()
        connect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect.settimeout(2)
        try:
            connect.connect((host, port))
            lock.acquire()
            print "%s open port %s %s" % (host, port, ports[port])
            lock.release()
            connect.close()
        except Exception, error:
            pass
        done.put(None)


def start_scan(number, ips, ports):
    lock = threading.Lock()
    queue = Queue.Queue()
    done_queue = Queue.Queue()
    for host in ips:
        for port in ports.keys():
            queue.put((host,port))
    while number:
        number -= 1
        create_thread = threading.Thread(target=scan_open_port_server, args=(done_queue, queue, ports, lock, ))
        create_thread.setDaemon(True)
        create_thread.start()
    while done_queue.qsize() < len(ips):
        sleep(10)

if __name__ == '__main__':
    usage="usage: l_scan.py -s 192.168.1.1 -e 192.168.1.254 -t 20"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-t", "--threads", dest="threads",help="Maximum threads, default 20")
    parser.add_option("-s", "--start-ip", dest="start_ip",help="start_ip")
    parser.add_option("-e", "--end-ip", dest="end_ip",help="end_ip")
    (options, args) = parser.parse_args()
    if not options.start_ip and not options.end_ip:
        parser.print_help()
        sys.exit()
    if options.threads is not None and int(options.threads) > 0:
        thread_number= int(options.threads)
    else:
        thread_number= 20

    start_ip =str(options.start_ip)
    end_ip = str(options.end_ip)
   # port_list = {80:"web",8080:"web",3311:"kangle",3312:"kangle",3389:"rdp",4440:"rundeck",5672:"rabbitMQ",5900:"vnc",6082:"varnish",7001:"weblogic",8161:"activeMQ",8649:"ganglia",9000:"fastcgi",9090:"ibm",9200:"elasticsearch",9300:"elasticsearch",9999:"amg",10050:"zabbix",11211:"memcache",27017:"mongodb",28017:"mondodb",3777:"",50000:"sap netweaver",50060:"hadoop",50070:"hadoop",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",123:"ntp",161:"snmp",8161:"snmp",162:"snmp",389:"ldap",443:"ssl",512:"rlogin",513:"rlogin",873:"rsync",1433:"mssql",1080:"socks",1521:"oracle",1900:"bes",2049:"nfs",2601:"zebra",2604:"zebra",2082:"cpanle",2083:"cpanle",3128:"squid",3312:"squid",3306:"mysql",4899:"radmin",8834:'nessus',4848:'glashfish'}
    port_list = {
        80: "web"
    }

    start_time = time.time()
    ip_list = ip_range(start_ip, end_ip)
    print "Start %s ip..." % str(len(ip_list))
    start_scan(thread_number, ip_list, port_list)
    print "End %.2f" % float(time.time() - start_time)

