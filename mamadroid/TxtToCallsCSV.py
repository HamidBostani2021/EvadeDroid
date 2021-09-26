from time import time
import csv
import os
import subprocess
import numpy as np

# Changes calls format. Previous format for each line is 'APICallX'===>['NextCall1','NextCall2'...] according to all the times APICallX is called. The resulting file will have each line as 'APICallX'\t'NextCall1'\t'NextCall2'\t... 
def main(WHICHSAMPLES,wf,_app_dir):
    alldb=[]
    allapps=[]
    for v in range (0,len(WHICHSAMPLES)):
        onedb=[]
        numApps=os.listdir(_app_dir + '/graphs/'+WHICHSAMPLES[v]+'/')

        allapps.append(numApps)
        leng=len(numApps)
        Fintime=[]
        checks=[0,999,1999,2999,3999,4999,5999,6999,7999,8999,9999,10999,11999,12999]
        
        path = _app_dir + '/Calls/'+WHICHSAMPLES[v]
        if os.path.exists(path):
            temp_list = os.listdir(path)
        else:
            os.mkdir(path)
            temp_list = list()
        
        for i in range (0,len(numApps)): 
            '''
            if i == 10864:
                break
            '''
            wholefile = []
            
            if numApps[i] in temp_list:
                
                if i%1000 == 0 or i>10853:
                    print("Exists App %d: %s" % (i,str(numApps[i])))
                
                path = os.path.join(_app_dir + '/Calls/'+WHICHSAMPLES[v],numApps[i])
                with open(path) as f:
                    content = f.readlines()
                if i%1000 == 0 or i>10853:
                    print("length content: %d"%(len(content)))
                wholefile = content
            if len(wholefile) == 0: 
                if i%1000 == 0 or i>10700:
                    print("Not exist App %d: %s" % (i,str(numApps[i])))
                if i in checks:
                    print ('starting ',i+1,' of ',leng)
                with open(_app_dir + '/graphs/'+WHICHSAMPLES[v]+'/'+str(numApps[i])) as callseq:
                    specificapp=[]
                    for line in callseq:
                            specificapp.append(line)
                    callseq.close()
    
                call=[]
                nextblock=[]
                nextcall=[]
                Startime= time()
                for line in specificapp:
                    if (line[0]=='<' and (line[1]=="'" or line[1].isalpha())):
                        call.append(str(line.split('(')[0]))
                        nextblock.append(str(line.split('==>')[1]))
    
                for j in range (0,len(nextblock)):
    
                    #supporto=nextblock[j].translate(None, '[]\'\\')
                    #https://www.py4u.net/discuss/216385
                    map = str.maketrans('', '', '[]\'\\')
                    supporto=nextblock[j].translate(map)
                    supporto=supporto.replace('\n','')
    
                    nextcall.append([])
                    nextcall[j]=(supporto.split(','))
                Fintime.append(time()-Startime)
                wholefile=[] 
                for j in range (0, len(call)):
                    eachline=call[j]+'\t'
                    for k in range (0,len(nextcall[j])):
                        tagliaparam=nextcall[j][k].split('(')[0]
                        eachline=eachline+tagliaparam+'\t'
                    wholefile.append(eachline)
    
                wf = 'Y'
                if wf=='Y':
                    print("App %d: %s" % (i,str(numApps[i])))
                    f = open(_app_dir + '/Calls/'+WHICHSAMPLES[v]+'/'+str(numApps[i]), 'w') 
                    for line in wholefile:
                        f.write(str(line)+'\n')
                    f.close
            onedb.append(wholefile)
            
            
            
        alldb.append(onedb)    
    return alldb,allapps

if __name__ == "__main__":
    _app_dir = "C:/GitLab/end-to-end_black-box_evasion_attack/mamadroid"
    WHICHSAMPLES = ["dataset_inaccessible"]
    main(WHICHSAMPLES,'Y',_app_dir)
    
            
