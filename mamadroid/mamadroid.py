'''
info: This is the first script to run after succesfully compiling the Appgraph.java file. 
It uses soot to generate the callgraph and parses the graph and abstract the API calls for use by the MaMaStat.py script. 
It accepts two arguments using the -f (or --file ) and -d (or --dir) options which specifies respectively, the APK file 
(or directory with APK files) to analyze and the to your Android platform directory. Use the -h option to view the help message. 
You can also edit the amount of memory allocated to the JVM heap space to fit your machine capabilities.
'''
import glob
import os 
#from subprocess import Popen, PIPE
import subprocess
from mamadroid import parseGraph

import argparse
from mamadroid import abstractGraph

from settings import config
from datetime import datetime
import lib.utils as utils
import torch
from itertools import repeat
mp = torch.multiprocessing.get_context('forkserver')


def parseargs():
    parser = argparse.ArgumentParser(description = "MaMaDroid - Analyze Android Apps for Maliciousness. For optimum performance, run on a machine with more than 16G RAM. Minimum RAM requirement is 4G.")
    parser.add_argument("-f", "--file", help="APK file to analyze or a directory with more than one APK to analyze.", type=str, required=True) 
    parser.add_argument("-d", "--dir", help="The path to your Android platform directory", type=str, required=True)
    args = parser.parse_args()
    return args


def _make_dirs(_base_dir, db):
    try:
        os.mkdir(_base_dir + "/graphs/" + db)
        os.mkdir(_base_dir + "/package/" + db)
        os.mkdir(_base_dir + "/family/" + db)
        os.mkdir(_base_dir + "/class/" + db)
    except OSError:
        print ("MaMaDroid Info: One or more of the default directory already exists. Skipping directory creation...")


def _repeated_function(app, _app_dir, db):
    try:
        if os.path.isfile(app + ".txt"):
            print ("MaMaDroid Info: Finished call graph extraction, now parsing...")
            _graphFile = parseGraph.parse_graph(app + ".txt", _app_dir, db)
            print ("MaMaDroid Info: Finished parsing the graph, now abstracting...")
            abstractGraph._preprocess_graph(_graphFile, _app_dir, db)
            #os.remove(app + ".txt")
            print ("MaMaDroid Info: Finished preprocessing the graph ...")
        else:
            print ("MaMaDroid Info: There was an error extracting call graphs from", app)
    except Exception as err:
        print ("MaMaDroid Info:", err)


def api_sequence_extraction(apks_path, db):
    #_base_dir = os.getcwd()    
    _app_dir = config['mamadroid']
    output_dir = config['mamadroid'] + '/call_graphs/'
    jar_path = config['soot']
    _make_dirs(_app_dir, db)
    androidPlatform = config["android_sdk"] + 'platforms/'
    '''
    i = 1
    #for app in glob.glob(app_path + "/*.apk"):
    for app in apks_path:
        if '.apk' not in app:
            continue
        print("i = " + str(i))
        try:            
            cmd = [config['java_sdk'] + 'java', '-jar', config['appgraph'], app,
                 androidPlatform, output_dir, jar_path]
            #print("cmd: "+ str(cmd))
            out = subprocess.check_output(cmd
                , stderr=subprocess.PIPE,
                timeout=config['extractor_timeout'])
            out = str(out, 'utf-8')
            #print("out: "+ str(out))
            if "call graph was extracted successfully" in out:   
                app = _app_dir + '/call_graphs/' + os.path.basename(app).replace('.apk','')
                _repeated_function(app, _app_dir, db)            
            i += 1
            
        except Exception as e:
           print(e.output)  
    ''' 
    print("No of apps for extracting feature: " + str(len(apks_path)))
    serial = True   
    cnt  = 1
    
    #These statements are for preventing to repeate checking apps that we have tried to create API call
    #because we may be disconnected from our machine in middle of creating API calls for apps
    #The name of apps will be read for log file
    #We should comment them when we want to to use this module in evasion module
    '''
    log_path = os.path.join(config["project_root"] , "log.txt")
    a_file = open(log_path, "r")
    list_of_lists = [(line.strip()).split() for line in a_file]    
    mamadroid_list = [os.path.basename(val[7]) for val in list_of_lists if val[0] == 'mamadroid']
    mamadroid_list = set(mamadroid_list)
    mamadroid_list = (list(mamadroid_list))
    '''
    mamadroid_list = list()
    
    if serial == True :
        for app in apks_path:                
            extract_api_calls(app, androidPlatform,output_dir,jar_path, db,_app_dir,mamadroid_list)
            print("number of checked apps: ", cnt)
            cnt += 1
    else:
        with mp.Pool(processes=config['nprocs_evasion']) as p:
                p.starmap(extract_api_calls, zip(apks_path,                                            
                                                    repeat(androidPlatform),
                                                    repeat(output_dir),
                                                    repeat(jar_path),
                                                    repeat(db),
                                                    repeat(_app_dir),
                                                    repeat(mamadroid_list)))
 
def extract_api_calls(app, androidPlatform,output_dir,jar_path, db,_app_dir,mamadroid_list):    
    
    if '.apk' not in app:
        return  
    if os.path.basename(app) in mamadroid_list:
        print("%s has already been failed" %(os.path.basename(app)))
        return
    apps_done = os.listdir(os.path.join(_app_dir,'graphs',db))
    if os.path.basename(app).replace('.apk','.txt') in apps_done:
        return
    try:   
        cmd = [config['java_sdk'] + 'java', '-jar', config['appgraph'], app,
             androidPlatform, output_dir, jar_path]
        #print("cmd: "+ str(cmd))
        out = subprocess.check_output(cmd
            , stderr=subprocess.PIPE,
            timeout=config['extractor_timeout'])
        out = str(out, 'utf-8')
        #print("out: "+ str(out))
        if "call graph was extracted successfully" in out:   
            app = _app_dir + '/call_graphs/' + os.path.basename(app).replace('.apk','')
            _repeated_function(app, _app_dir, db)
        '''
        if i == 10:
            return
        '''
        no_finished_apps = len(os.listdir(os.path.join(_app_dir,'graphs',db)))
        print("no_finished_apps = " + str(no_finished_apps))
        
    except Exception as e:
       #print(e.output) 
       print("Failed to generate call graph: " + str(app))
       utils.perform_logging("mamadroid module - datetime: " + str(datetime.now()) +" app: " + str(app))

'''
if __name__ == "__main__":
    api_sequence_extraction()
'''
