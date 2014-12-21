import json
import sys
import os


cols='count,rrtype,rrname,zone_time_first,zone_time_last,time_first,time_last,rdata'
col_list=cols.split(',')
for fname in os.listdir(sys.argv[1]):
	fin=open(sys.argv[1]+fname,'rb')
	fout=open(sys.argv[1]+fname+".csv",'wb')
	fout.write(cols+'\n')

	for line in fin.readlines():
	    try:
		jdata=json.loads(line)
	    except:
		continue
	    for key in col_list:
		try:
		    if key=='rdata':
			fout.write('"'+str(jdata[key])+'"')
		    else: 
			fout.write('"'+str(jdata[key])+'",')
		except:
		    fout.write('"",')
	    fout.write('\n')

	fin.close()
	fout.close()
sys.exit(0)
