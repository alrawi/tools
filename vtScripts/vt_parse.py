from bs4 import BeautifulSoup as soup
import re
import requests
import random
import Queue
import sys
import threading
import time
import pickle
import json


base_url="https://www.virustotal.com/en/ip-address/%s/information/"

ua_list=[
	'Mozilla/5.0 (Windows NT 5.1; rv:9.0.1) Gecko/20100101 Firefox/9.0.1',
	'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; Maxthon/3.0)',
	'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; TheWorld)',
	'Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14',
	'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6b) Gecko/20031212 Firebird/0.7+',
	'Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101 Firefox/28.0',
	'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
	'Lynx/2.8.8dev.3 libwww-FM/2.14 SSL-MM/1.4.1'
] #user-agent list
proxy_base="https://%s:%s@%s.perfect-privacy.com:443"
proxy_prt=[8080, 3128, 312, 443]
proxy_pnts=['amsterdam1','amsterdam2','bucharest','erfurt',
    'frankfurt','huenenberg','nuremberg1','nuremberg2',
    'paris','rotterdam1','rotterdam2','steinsel1','steinsel2',
    'brisbane','cairo','hongkong','istanbul','kiev','london1',
    'london2','montreal1','montreal2','moscow1','moscow2','newyork1',
    'newyork2','panama-city','reykjavik','saopaulo','singapore',
    'stockholm1','stockholm2','telaviv','tokyo','vilnius','zurich'
] #proxy points


def get_url(ip, loc=proxy_pnts[8]):
    proxies={'https':proxy_base%(creds[0],creds[1],loc)} # setup proxy
    headers={
        'User-Agent': ua_list[random.randint(0,len(ua_list)-1)]
        } # pick a random user agent

    try:
        #try request, proxies might be non-responsive
        r=requests.get(base_url%(ip), verify=False,headers=headers,proxies=proxies,timeout=10) # perform get request 
    except:
        #push ip back to work queue
        ipq.put(ip) #failed ip reprocess
        return
    root=soup(r.text) # parse html result
    detect_tag=root.findAll(id=re.compile("^detected-.*")) # find detected sections
    dict_list=[] # temp dictionary to add sections to
    if len(detect_tag)>0: # check if we have any detected tags
        for tmp in detect_tag: # iterate on each detected section
            secName=tmp.get('id') # get section name
            divs=tmp.findAll("div") # get all elements under section
            tmpl=[] # temp list to store each element
            for e in divs: # iterate on each element in each section
                entries=[] # list for components under each element
                for c in e.findAll(True): # get each component under each element
                    entries.append(c.string.strip()) # add component to list
                tmpl.append(entries) # add element to list
            dict_list.append({secName:tmpl}) # add section to dictionary
    rsltq.put((ip,dict_list))


def work():
    while not ipq.empty():
        ip=ipq.get()
        get_url(ip,proxy_pnts[random.randint(0,len(proxy_pnts)-1)])
        time.sleep(0.5)

def dumpQ(stop_cnt=0):
    wrt_cnt=0
    output=open(sys.argv[2],'wb')
    print "opened file"
    while True:
        if wrt_cnt==stop_cnt:
            output.close()
            return
        try:
            rcrd=rsltq.get(False)
            output.write(rcrd[0]+delim+json.dumps(rcrd[1])+nl)
            print "writing successful"
        except:
            print "writing record failed"
            time.sleep(5.0)
            continue



def init():
    #read in IPs
    ips=open(sys.argv[1],'rb').readlines()
    ips_cnt=len(ips)
    #queue IPs
    for ip in ips:
        ipq.put(ip.strip())

    thrd_list=[] #thread list, holds running threads
    #start work threads
    for i in range(0,len(proxy_pnts)-3):
        tmpt=threading.Thread(target=work)
        tmpt.start()
        thrd_list.append(tmpt)
    
    #Dump records to disk
    write_t=threading.Thread(target=dumpQ, args=(ips_cnt,))
    write_t.start()

    #join running threads before exiting
    for t in thrd_list:
        t.join()
    
    #pickle Queue to disk
    write_t.join()

if len(sys.argv)==5:
    creds=(sys.argv[3],sysargv[4]) #creds for the proxies
    ipq=Queue.Queue() #ip queue
    rsltq=Queue.Queue() #result queue
    delim='***$***' #delimiter for output data
    nl='\n'
    #Let's get the party started
    init()
else: #usage, lazy version
    print "\nThis script is used to get data from VT via PP proxies. Supply a list of IP addresses"
    print "provide an output file name for the data to be dumped to, and supply username and "
    print "passowrd for PP.\n"
    print "Usage: python %s [input_filename] [output_filename] [ppUsername] [ppPassword]\n"%(sys.argv[0])
#pp.pprint(get_url(base_url%(ip)))
