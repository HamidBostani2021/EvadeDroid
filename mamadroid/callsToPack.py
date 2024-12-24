import csv
from time import time
import os
import subprocess
from multiprocessing import Pool,Process,Queue
import numpy as np
from mamadroid import PackAbs as Pk

from settings import config

# This script does the abstraction to packages of the API calls.


# This function is called when -wf flag is set to Y to operate the abstraction.
def fileextract (fileitem,numApps,WHICHSAMPLES,v,PACKETS,pos):
    Packetsfile=[]
    
    with open(config['mamadroid'] + '/Calls/'+WHICHSAMPLES[v]+'/'+str(fileitem)) as callseq:
        specificapp=[]

        for line in callseq:
            Packetsline=[]

            for j in line.split('\t')[:-1]:
                match = None
                j = j.replace('<','')
                j = j.replace(' ','')

                match=Pk.PackAbs(j,pos)

                if match == None:

                    splitted = j.split('.')
                    obfcount=0
                    for k in range (0,len(splitted)):
                        if len(splitted[k])<3:
                            obfcount+=1
                    if obfcount>=len(splitted)/2:
                        match='obfuscated'
                    else:
                        match='selfdefined'
                Packetsline.append(match)
            Packetsfile.append(Packetsline)
        callseq.close()

    f = open(config['mamadroid'] + '/Packages/'+WHICHSAMPLES[v]+'/'+str(fileitem), 'w') 
    print("start to write pk: %s" %(fileitem))
    for j in range (0, len(Packetsfile)):

        eachline=''
        for k in range (0,len(Packetsfile[j])):

            eachline=eachline+Packetsfile[j][k]+'\t'

        f.write(str(eachline)+'\n')    
    f.close
    print("fileitem: %s" %(fileitem))

# The main function. Inputs are explained in MaMaStat.py. In case -wf is set to N the abstraction is operated in the else and not multiprocessed. The abstraction process is differen from the families one to make it more time efficient.
def main(WHICHSAMPLES,wf,CORES,callsdatabase=None):
    PACKETS=[]
    Fintime=Queue()
    with open(config['mamadroid'] + '/Packages.txt') as packseq:
        for line in packseq:
            PACKETS.append(line.replace('\n',''))
    packseq.close()
    allpacks=[]
    for i in PACKETS:
        #allpacks.append(i.split('.')[1:])
        i = i.split(':')[0]
        allpacks.append(i.split('.')[0:])
    pos=[[],[],[],[],[],[],[],[],[]]
    for i in allpacks:
        k=len(i)
        for j in range(0,k):

            if i[j] not in pos[j]:
                pos[j].append(i[j])


    packdb=[]
    if wf=='Y':
        for v in range (0,len(WHICHSAMPLES)):
            numApps=os.listdir(config['mamadroid'] + '/Calls/'+WHICHSAMPLES[v]+'/')

            for i in range (0,len(numApps)):
                fileitem = numApps[i]
                fileextract(fileitem,numApps,WHICHSAMPLES,v,PACKETS,pos)
            '''
            queue = Queue()
            for i in range (0,len(numApps)):
                queue.put(numApps[i])

            appslist=[]
            leng=len(numApps)
            ProcessList=[]
            numfor=np.min([leng,CORES])
            for rr in range (0,numfor):
                fileitem=queue.get()
                ProcessList.append(Process(target=fileextract, args=(fileitem,numApps,WHICHSAMPLES,v,PACKETS,pos)))
                ProcessList[rr].daemon = True
                ProcessList[rr].start() 

            while queue.empty()==False:

                for rr in range (0,CORES):
                    
                    if (ProcessList[rr].is_alive()==False):
                        ProcessList[rr].terminate()
                        
                        if (queue.empty()==False):
                        
                            fileitem=queue.get()
                            ProcessList[rr]=Process(target=fileextract, args=(fileitem,numApps,WHICHSAMPLES,v,PACKETS,pos))
                            ProcessList[rr].daemon = True
                            ProcessList[rr].start() 
                
            for rr in range (0,len(ProcessList)):        
                ProcessList[rr].join()
            '''

    else:
        for db in callsdatabase:
            appdb=[]
            cnt = 0
            for app in db:          
                Packetsfile=[]
                for line in app:
                    Packetsline=[]
                    for j in line.split('\t')[:-1]:
                        match = None
                        j = j.replace('<','')
                        j = j.replace(' ','')
                        
                        match=Pk.PackAbs(j,pos)
                        
                        if match == None:
                        
                            splitted = j.split('.')
                            obfcount=0
                            for k in range (0,len(splitted)):
                                if len(splitted[k])<3:
                                    obfcount+=1
                            if obfcount>=len(splitted)/2:
                                match='obfuscated'
                            else:
                                match='selfdefined'
                        Packetsline.append(match)
                    Packetsfile.append(Packetsline)                
                appdb.append(Packetsfile) 
                cnt += 1
                print("App %d: %s" % (cnt,str(app)))
            packdb.append(appdb)
    return packdb
    
