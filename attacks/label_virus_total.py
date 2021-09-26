# -*- coding: utf-8 -*-
"""
Querying VirusTotal
"""
import pickle
#from settings import config
config = list()
import shutil
import time


#https://virustotal.github.io/vt-py/quickstart.html
#import nest_asyncio
#nest_asyncio.apply()

import requests
import os
#https://developers.virustotal.com/
def scan(app_path):  

    url = 'https://www.virustotal.com/vtapi/v2/file/scan'    
    apikey_val = '...'
    params = {'apikey': apikey_val}    
    files = {'file': (os.path.basename(app_path), open(app_path, 'rb'))}    
    response = requests.post(url, files=files, params=params)    
    print(response.json())
    return response.json()['resource']

def report(app_path):   
    resource = scan(app_path)
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    apikey_val = '...'
    params = {'apikey': apikey_val, 'resource': resource}
    
    response = requests.get(url, params=params)
    print("response_code", response.json()['response_code'])
    while response.json()['response_code'] != 1:
        time.sleep(5)
        response = requests.get(url, params=params)
        print("response_code", response.json()['response_code'])
    
    print("response_code: ", response.json()['response_code'])
    
    print("%s VT detections out of %s: " %(str(response.json()['positives']),str(response.json()['total'])))
    try:
        Kaspersky = response.json()['scans']['Kaspersky']['detected']
    except:
        Kaspersky = False
        
    try:
        Symantec = response.json()['scans']['Symantec']['detected']
    except:
        Symantec = False
        
    try:
        McAfee = response.json()['scans']['McAfee']['detected']
    except:
        McAfee = False
        
    try:
        Microsoft = response.json()['scans']['Microsoft']['detected']
    except:
        Microsoft = False
        
    try:
        TrendMicro = response.json()['scans']['TrendMicro']['detected']
    except:
        TrendMicro = False
        
    try:
        Malwarebytes = response.json()['scans']['Malwarebytes']['detected']
    except:
        Malwarebytes = False
        
    try:
        ESETNOD32 = response.json()['scans']['ESET-NOD32']['detected']
    except:
        ESETNOD32 = False
        
    try:
        Sophos = response.json()['scans']['Sophos']['detected']
    except:
        Sophos = False
        
    try:
        Panda = response.json()['scans']['Panda']['detected']
    except:
        Panda = False
        
    try:
        BitDefender = response.json()['scans']['BitDefender']['detected']
    except:
        BitDefender = False
        
    print(response.json())
    return response.json()['positives'],Kaspersky,Symantec,McAfee,Microsoft,TrendMicro,Malwarebytes,ESETNOD32,Sophos,Panda,BitDefender

def select_candidate_malware_for_virustotal():
    base_path = os.path.join(config['results_dir'],'EvadeDroid/Drebin/result-noquery_20-size_0.500000-hardlabel_1')
    
    #"C:/GitLab/end-to-end_black-box_evasion_attack/data/stored-components/attack-results/EvadeDroid/Drebin/result-noquery_20-size_0.500000-hardlabel_1
    
    apk_name = os.listdir(base_path)
    cnt_detect = 0
    cnt = 0
    for app in apk_name: 
        cnt += 1
        if cnt < 200:
            print("app: %s - cnt: %d" %(os.path.splitext(app)[0] + '.apk',cnt))
            continue
        apps_checked = os.listdir(os.path.join(config['apks_accessible'],'malware_for_vt_back'))
        if os.path.splitext(app)[0] + '.apk' in apps_checked:
            #cnt += 1
            cnt_detect += 1
            print("%s has already checked"%(app))
            continue
        apk_info_path = os.path.join(base_path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.adv_malware_label == 0 and apk.number_of_queries < 2:
            #cnt += 1
            print("app: %s - cnt: %d" %(os.path.splitext(app)[0] + '.apk',cnt))
            app_path = os.path.join(config['apks_accessible'],'malware',os.path.splitext(app)[0] + '.apk')
            try:
                no_detection,_,_,_,_,_,_,_,_,_,_ = report(app_path)
                if no_detection >= 5:                
                    destination = os.path.join(config['apks_accessible'],'malware_for_vt',os.path.splitext(app)[0] + '.apk')
                    shutil.copy(app_path, destination)
                    cnt_detect += 1
                    print("cnt_detect: ", cnt_detect)
                    if cnt_detect == 100:
                        break
            except:
                continue
                
def malware_detection_with_vt():
    base_path = os.path.join(os.path.join(config['apks_accessible'],'malware_for_vt'))
    apk_name = os.listdir(base_path)
    
    cnt = 0
    for app in apk_name:    
        '''
        apps_checked = os.listdir(os.path.join(config['apks_accessible'],'malware_for_vt'))
        if os.path.splitext(app)[0] + '.apk' in apps_checked:
            cnt += 1
            cnt_detect += 1
            print("%s has already checked"%(app))
            continue
        '''        
        app_path = os.path.join(config['apks_accessible'],'malware_for_vt',os.path.splitext(app)[0] + '.apk')
        _,Kaspersky,Symantec,McAfee,Microsoft,TrendMicro,Malwarebytes,ESETNOD32,Sophos,Panda,BitDefender = report(app_path)
        cnt += 1
        print("Kaspersky: ",Kaspersky)
        print("Symantec: ",Symantec)
        print("McAfee: ",McAfee)
        print("Microsoft: ",Microsoft)
        print("TrendMicro: ",TrendMicro)
        print("Malwarebytes: ",Malwarebytes)
        print("ESETNOD32: ",ESETNOD32)
        print("Sophos: ",Sophos)
        print("Panda: ",Panda)
        print("BitDefender: ",BitDefender)
        print("cnt:%d ----------------"%(cnt))
        if Kaspersky == True:
            destination = os.path.join(config['apks_accessible'],'vt_engines/Kaspersky',os.path.splitext(app)[0] + '.apk')
            shutil.copy(app_path, destination)
        
        if Symantec == True:
            destination = os.path.join(config['apks_accessible'],'vt_engines/Symantec',os.path.splitext(app)[0] + '.apk')
            shutil.copy(app_path, destination)
        
        if McAfee == True:
            destination = os.path.join(config['apks_accessible'],'vt_engines/McAfee',os.path.splitext(app)[0] + '.apk')
            shutil.copy(app_path, destination)
        
        if Microsoft == True:
            destination = os.path.join(config['apks_accessible'],'vt_engines/Microsoft',os.path.splitext(app)[0] + '.apk')
            shutil.copy(app_path, destination)
        
        if TrendMicro == True:
            destination = os.path.join(config['apks_accessible'],'vt_engines/TrendMicro',os.path.splitext(app)[0] + '.apk')
            shutil.copy(app_path, destination)
    
        if Malwarebytes == True:
            destination = os.path.join(config['apks_accessible'],'vt_engines/Malwarebytes',os.path.splitext(app)[0] + '.apk')
            shutil.copy(app_path, destination)
            
        if ESETNOD32 == True:
            destination = os.path.join(config['apks_accessible'],'vt_engines/ESETNOD32',os.path.splitext(app)[0] + '.apk')
            shutil.copy(app_path, destination)
            
        if Sophos == True:
            destination = os.path.join(config['apks_accessible'],'vt_engines/Sophos',os.path.splitext(app)[0] + '.apk')
            shutil.copy(app_path, destination)
            
        if Panda == True:
            destination = os.path.join(config['apks_accessible'],'vt_engines/Panda',os.path.splitext(app)[0] + '.apk')
            shutil.copy(app_path, destination)
            
        if BitDefender == True:
            destination = os.path.join(config['apks_accessible'],'vt_engines/BitDefender',os.path.splitext(app)[0] + '.apk')
            shutil.copy(app_path, destination)


