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
    
    params = {'apikey': '', 'resource': resource}   
    
    response = requests.get(url, params=params)
    
    while response.json()['response_code'] != 1:
        time.sleep(5)
        response = requests.get(url, params=params)
        print("response_code", response.json()['response_code'])   
   
    
    print("%s VT detections out of %s: " %(str(response.json()['positives']),str(response.json()['total'])))
    try:
        Kaspersky = response.json()['scans']['Kaspersky']['detected']
    except:
        Kaspersky = False
        
    try:
        Avast = response.json()['scans']['Avast']['detected']
    except:
        Avast = False
        
    try:
        McAfee = response.json()['scans']['McAfee']['detected']
    except:
        McAfee = False
        
    try:
        AvastMobile = response.json()['scans']['Avast-Mobile']['detected']
    except:
        AvastMobile = False
        
    try:
        Avira = response.json()['scans']['Avira']['detected']
    except:
        Avira = False
                   
    try:
        FSecure = response.json()['scans']['F-Secure']['detected']
    except:
        FSecure = False 
        
    try:
        Ikarus = response.json()['scans']['Ikarus']['detected']
    except:
        Ikarus = False
        
    try:
        BitDefender = response.json()['scans']['BitDefender']['detected']
    except:
        BitDefender = False
        
    try:
        BitDefenderFalx = response.json()['scans']['BitDefenderFalx']['detected']
    except:
        BitDefenderFalx = False
        
    try:
        BitDefenderTheta = response.json()['scans']['BitDefenderTheta']['detected']
    except:
        BitDefenderTheta = False        
    
    return response.json()['positives'],Kaspersky, Avast, McAfee, AvastMobile, Avira, FSecure, Ikarus, BitDefender, BitDefenderFalx, BitDefenderTheta


def select_candidate_malware_for_virustotal():
    base_path = os.path.join(config['results_dir'],'EvadeDroid/Drebin/result-noquery_20-size_0.500000-hardlabel_1')         
    apk_name = os.listdir(base_path)
    cnt_detect = 0
    cnt = 0
    for app in apk_name: 
        cnt += 1
        print("app: %s - cnt: %d" %(os.path.splitext(app)[0] + '.apk',cnt))       
        app_path = os.path.join(config['apks_accessible'],'malware',os.path.splitext(app)[0] + '.apk')
        try:
            no_detection,Kaspersky, Avast, McAfee, AvastMobile, Avira, FSecure, Ikarus, BitDefender, BitDefenderFalx, BitDefenderTheta = report(app_path)
            if no_detection >= 5:                
                destination = os.path.join(config['apks_accessible'],'malware_for_vt',os.path.splitext(app)[0] + '.apk')
                shutil.copy(app_path, destination)
                cnt_detect += 1
                print("cnt_detect: ", cnt_detect)
                
                print("----------------")
                print("Kaspersky: ",Kaspersky)
                print("Avast: ",Avast)
                print("McAfee: ",McAfee)
                print("AvastMobile: ",AvastMobile)
                print("Avira: ",Avira)
                print("F-Secure: ",FSecure)
                print("Ikarus: ",Ikarus)
                print("BitDefender: ",BitDefender)
                print("BitDefenderFalx: ",BitDefenderFalx)
                print("BitDefenderTheta: ",BitDefenderTheta)
                print("cnt:%d ----------------"%(cnt))
                if Kaspersky == True:
                    destination = os.path.join(config['apks_accessible'],'vt_engines/Kaspersky',os.path.splitext(app)[0] + '.apk')
                    shutil.copy(app_path, destination)
                
                if Avast == True:
                    destination = os.path.join(config['apks_accessible'],'vt_engines/Avast',os.path.splitext(app)[0] + '.apk')
                    shutil.copy(app_path, destination)
                
                if McAfee == True:
                    destination = os.path.join(config['apks_accessible'],'vt_engines/McAfee',os.path.splitext(app)[0] + '.apk')
                    shutil.copy(app_path, destination)
                
                if AvastMobile == True:
                    destination = os.path.join(config['apks_accessible'],'vt_engines/AvastMobile',os.path.splitext(app)[0] + '.apk')
                    shutil.copy(app_path, destination)
                
                if Avira == True:
                    destination = os.path.join(config['apks_accessible'],'vt_engines/Avira',os.path.splitext(app)[0] + '.apk')
                    shutil.copy(app_path, destination)
            
                if FSecure == True:
                    destination = os.path.join(config['apks_accessible'],'vt_engines/FSecure',os.path.splitext(app)[0] + '.apk')
                    shutil.copy(app_path, destination)
                    
                if Ikarus == True:
                    destination = os.path.join(config['apks_accessible'],'vt_engines/Ikarus',os.path.splitext(app)[0] + '.apk')
                    shutil.copy(app_path, destination)
                    
                if BitDefender == True:
                    destination = os.path.join(config['apks_accessible'],'vt_engines/BitDefender',os.path.splitext(app)[0] + '.apk')
                    shutil.copy(app_path, destination)
                    
                if BitDefenderFalx == True:
                    destination = os.path.join(config['apks_accessible'],'vt_engines/BitDefenderFalx',os.path.splitext(app)[0] + '.apk')
                    shutil.copy(app_path, destination)
                    
                if BitDefenderTheta == True:
                    destination = os.path.join(config['apks_accessible'],'vt_engines/BitDefenderTheta',os.path.splitext(app)[0] + '.apk')
                    shutil.copy(app_path, destination)
                
                if cnt_detect == 100:
                    break
        except:
            continue
