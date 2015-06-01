import pefile
import sys
import os
import hashlib
import json
import threading
import time
from Queue import Queue
from certExtract import dump_content


#accounting vars
certQueue=Queue()
fileQueue=Queue()
fault=0
total=0
count=0
nthds=40 # number of processing threads
dqths=5 # number of dequeuing threads
path=sys.argv[1]+'/'
pathd=sys.argv[3]+'/'
outfile=open(sys.argv[2],'wb')
outfile.write('[')
run=False

def processFile(f=None):
    if f==None:
        return None
    fStream=open(f,'rb').read()
    m=hashlib.sha1()
    m.update(fStream)
    key=m.hexdigest()
    m=None
    try:
        pe=pefile.PE(data=fStream, fast_load=False)
    except Exception as e:
        sys.stderr.write("processFile 1: %s\n"%(e.message))
        return None 

    try:
        #get cert vAddr and size, if exists
        dAddr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
        dSize = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
        if dAddr!=0 or dSize!=0:
            cert=pe.write()[dAddr+8:dAddr+8+dSize]
            m=hashlib.sha1()
            m.update(cert)
            cert_key=m.hexdigest()
            m=None
            rslt=dump_content(cert)
            if rslt==None:
                return None
            else:
                return {key:{cert_key:rslt}}
    except Exception as e:
        sys.stderr.write("processFile 2: %s\n"%(e.message))
        return None

    pe=None
    return None

def queueFiles(path=None):
    global count
    if path == None:
        return
    for f in os.listdir(path):
        try:
            fileQueue.put(path+f, timeout=5)
            count+=1
        except Exception as e:
            sys.stderr.write("queuingFiles: %s\n"%(e.message))
            pass

def dequeueCerts():
    global total
    while run:
        try:
            outfile.write(json.dumps(certQueue.get_nowait(), indent=4)+',')
            total+=1
        except Exception as e:
            sys.stderr.write("dequeueCerts: %s\n"%(e.message))
            time.sleep(10)

def threadFunc():
    global fault
    global pathd
    while run:
        try:
            fn=fileQueue.get_nowait()
            rslt=processFile(fn)
            fn=fn[fn.find('/')+1:]
            if rslt==None:
                fault+=1
            else:
                certQueue.put(rslt) #wait until a spot is available
                rslt=None
            os.rename(path+fn,pathd+fn)
        except Exception as e:
            sys.stderr.write("threadFunc: "+e.message+'\n')
            time.sleep(5)
            pass

def status():
    global count,fault,total
    while run:
        print "\n================================"
        print "length of cert queue ",certQueue.qsize()
        print "length of file queue ",fileQueue.qsize()
        print "Total certs extracted ",total
        print "Faulted samples ",fault
        print "Total files queued ",count
        print "================================\n"
        outfile.flush()
        sys.stdout.flush()
        time.sleep(10)


#init threads
pth=[]
fqth=threading.Thread(target=queueFiles, args=(path,))
sth=threading.Thread(target=status)
dqth=[]
for i in range(0,dqths):
    dqth.append(threading.Thread(target=dequeueCerts))
for i in range(0,nthds):
    pth.append(threading.Thread(target=threadFunc))

#start threads
st=time.time()
print "starting file queueing thread..."
fqth.start()
run=True
time.sleep(2)
sth.start()
print "run status set to True"
for th in pth:
    th.start()
for th in dqth:
    th.start()


#clean up
fqth.join()
print "file queue thread joined, sleeping 30 sec"
while(fileQueue.qsize()>0):
    time.sleep(5)
while certQueue.qsize()>0:
    print "waiting for certQueue..."
    time.sleep(5)
run=False
print "awaken! joining running threads"
for th in pth:
    th.join()
for th in dqth:
    th.join()
outfile.write(']')
outfile.close()
print "done and done!"
print "Time to run", time.time()-st
print "\n================================"
print "length of cert queue ",certQueue.qsize()
print "length of file queue ",fileQueue.qsize()
print "Total certs extracted ",total
print "Faulted samples ",fault
print "Total files queued ",count
print "================================\n"
sys.exit(0)



open(sys.argv[2],"wb").write(json.dumps(output))
print len(output)
print "sigs found: %d\n"%(count)
print "fault processing %d\n"%(fault)
print "total %d\n"%(total)
sys.exit(0)


