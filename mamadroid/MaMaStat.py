from mamadroid import TxtToCallsCSV as TTC
from mamadroid import callsToFamilies as cTF
from mamadroid import callsToPack as cTP
from mamadroid import MarkovCall as MC

from settings import config

import os
import argparse
import sys
import multiprocessing
import math

def writelists (tbwritten,filepath):
    f = open(filepath, 'w') 
    for line in tbwritten:
        f.write(str(line)+'\n')    
    f.close

# This script manages the scripts related to the whole statistical model. Starting from the result of the static analysis, arrives to the generation of the csv file per database of samples.
# The script requires as input a python array of the names of the folders in the graph folder related to the databases which samples we want to extract the features. These folders must contain the files created by the static analysis. The python array structure has to be mantained even if there is only one database.
# It requires as well a flag (Y or N) if you desire to write the files during the intermediate steps (from the graph folder to the call to the families/package one). If the flag is set on N it will only write the final csv. When the flag is set on Y the script is a lot slowert output part.
# Indicate first the databases folders in this format: database1:database2:database3. Then indicate Y or N (--writefiles) as second argument.
# The features files (one per indicated database) will be created as "name_of_the_database".csv files in the folders Features/Families and Features/Packages.

def feature_extraction_markov_chain(dbs):
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument("-d","--database", help="specify the databases folder in graphs/ in which the samples are in this format: database1:database2:database3",
                        type=str)
    parser.add_argument("-wf","--writefiles", help="flag to write intermediate files or not, write -wf followed by Y or N",type=str)
    parser.add_argument("-c","--cores", type=int, help="Part of the scripts fork in more processes. default cores number is 75% of the cores of the machine, please specify if you want a different number.")
    args = parser.parse_args()
    if args.database:
        dbs=args.database.split(':')
    else:
        sys.exit("no database input. Please, check the help.")
    if args.writefiles:
        wflag=args.writefiles
    else:
        wflag='N'
        print ("no writefiles option used, the default option is not writing the intermediate files.")
    '''
    
    wflag = 'Y'
    _app_dir = config['mamadroid']
    
    print("wflag: %s"%(wflag))
    if wflag=='Y':        
        for i in dbs:
            print("db: %s"%(i))
            if os.path.isdir(os.path.join(_app_dir , 'Calls/' + i)) == False:
                print(os.path.join(_app_dir + 'Calls'))
                os.mkdir(os.path.join(_app_dir , 'Calls/' + i))
            print(os.path.join(_app_dir , 'Families/' + i))
            print(os.path.isdir(os.path.join(_app_dir , 'Families/' + i)))
            if os.path.isdir(os.path.join(_app_dir , 'Families/' + i)) == False:
                print("create db directory in Families")
                os.mkdir(os.path.join(_app_dir , 'Families/' + i))
            if os.path.isdir(os.path.join(_app_dir , 'Packages/' + i)) == False:
                print("create db directory in Packages")
                os.mkdir(os.path.join(_app_dir , 'Packages/' + i))           
    
    cores=int(math.ceil(0.75*multiprocessing.cpu_count()))
    print ("no cores option used, the default option is 75% cores.")    
    
    print ("starting rearranging the files")
    callsdatabase,appslist=TTC.main(dbs,wflag,_app_dir)    
    
    if wflag=='Y':
        callsdatabase=None
        print ("starting the abstraction to families")
        _=cTF.main(dbs,wflag,cores)
        print ("abstraction to families is finished")
        print ("starting the abstraction to packages")
        _=cTP.main(dbs,wflag,cores)
        print ("abstraction to packages is finished")
        print ("starting the Markov model creation in families abstraction")
        MC.main(dbs,wflag,'Families',_app_dir)
        print ("Markov model in families abstraction finished, features file created in Features/Families/")
        print ("starting the Markov model creation in packages abstraction")
        MC.main(dbs,wflag,'Packages',_app_dir)
        print ("Markov model in packages abstraction finished, features file created in Features/Packages/")
    else:
        print ("starting the abstraction to families")
        famdatabase=cTF.main(dbs,wflag,cores,callsdatabase)
        print ("abstraction to families is finished")
        print ("starting the abstraction to packages")
        packdatabase=cTP.main(dbs,wflag,cores,callsdatabase)
        callsdatabase=None
        print ("abstraction to packages is finished")
        print ("starting the Markov model creation in families abstraction")    
        MC.main(dbs,wflag,'Families',_app_dir, famdatabase,appslist)
        famdatabase=None
        print ("Markov model in families abstraction finished, features file created in Features/Families/")
        print ("starting the Markov model creation in packages abstraction")
        MC.main(dbs,wflag,'packages',_app_dir, packdatabase,appslist)
        packdatabase=None
        print ("Markov model in packages abstraction finished, features file created in Features/Packages/")

if __name__ == "__main__":
    feature_extraction_markov_chain()