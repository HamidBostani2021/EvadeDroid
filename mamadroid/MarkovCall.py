from mamadroid import Markov as mk
import os
from time import time
import numpy as np
import pickle

#Main script for the Markov modeling part. Inputs are explained in MaMaStat.py. Generates a csv file with the features per each row.
def main(WHICHSAMPLES,wf,WHICHCLASS,_app_dir,dbs=None,appslist=None):
    PACKETS=[]

    #with open(WHICHCLASS+'Occ.txt') as packseq:    
    with open(_app_dir + '/' + WHICHCLASS+'.txt') as packseq:    
        for line in packseq:
            if WHICHCLASS == 'Families':
                line = line.replace('\n','')
                line = line.split('.')[0]
            
            PACKETS.append(line.replace('\n',''))
    packseq.close()
    allnodes=PACKETS
    allnodes.append('selfdefined')
    allnodes.append('obfuscated')

    Header=[]
    Header.append('filename')
    for i in range (0,len(allnodes)):
        for j in range (0,len(allnodes)):
            Header.append(allnodes[i]+' To '+allnodes[j])
    print ('Header is long ',len(Header))

    Fintime=[]
    dbcounter=0
    for v in range (0,len(WHICHSAMPLES)):
        
        print("numApps: " + str(WHICHSAMPLES[v]))
        
        numApps=os.listdir(_app_dir + '/graphs/'+WHICHSAMPLES[v]+'/')

        DatabaseRes=[]
        DatabaseRes.append(Header)

        leng=len(numApps)
        checks=[0,999,1999,2999,3999,4999,5999,6999,7999,8999,9999,10999,11999,12999]
        for i in range (0,len(numApps)):
            print("App %d - %s"%(i,numApps[i]))
            if numApps[i] == "com.adsi.txt" \
            or numApps[i] == "com.arvatis.motorsporttotal.txt" \
            or numApps[i] == "com.craftmakingjewelrytutorials.bordinas.txt" \
            or numApps[i] == "com.fuelbuddyindia.txt" \
            or numApps[i] == "com.handcent.sms.skin.valentineday2012.txt" \
            or numApps[i] == "com.hometheaterroomsetupidea.bordinas.txt" \
            or numApps[i] == "com.milesstone.hinduweddingcardmaker.txt" \
            or numApps[i] == "com.mxtech.ffmpeg.tegra3.txt" \
            or numApps[i] == "com.tappsolutions.calc_sli_rate.txt" \
            or numApps[i] == "fit.guru.yoga.plugin60.txt" \
            or numApps[i] == "fit.yogamonkey.yoga.plugin78.txt":
                continue
            if i in checks:
                print ('starting ',i+1,' of ',leng)
            if wf=='Y':
                with open(_app_dir + '/' + WHICHCLASS+'/'+WHICHSAMPLES[v]+'/'+str(numApps[i])) as callseq:
                    specificapp=[]
                    for line in callseq:
                        specificapp.append(line)
                callseq.close()
            else:
                specificapp=[]
                for line in dbs[dbcounter][i]:
                    specificapp.append(line)
                    
            Startime=time()
            MarkMat=mk.main(specificapp,allnodes,wf)

            MarkRow=[]
            if wf=='Y':
                MarkRow.append(numApps[i])
            else:
                MarkRow.append(appslist[dbcounter][i])            
            for i in range (0,len(MarkMat)):
                for j in range (0,len(MarkMat)):
                    MarkRow.append(MarkMat[i][j])            
            
            DatabaseRes.append(MarkRow)
            Fintime.append(time()-Startime)
            
            
        dbcounter+=1
        '''
        f = open('Features/'+WHICHCLASS+'/'+WHICHSAMPLES[v]+'.csv', 'w')  
        for line in DatabaseRes:
            f.write(str(line)+'\n')
        f.close
        '''
        '''
        newfile = _app_dir + '/Features/'+WHICHCLASS+'/'+WHICHSAMPLES[v]+'.csv'
        with open(newfile, 'w') as out:
            for line in DatabaseRes:
                out.write(str(line)+'\n')
        '''
        newfile = _app_dir + '/Features/'+WHICHCLASS+'/'+WHICHSAMPLES[v]+'.p'
        with open(newfile, 'wb') as f:
            pickle.dump(DatabaseRes, f) 

