
"""
evasion.py
~~~~~~~~~~

Transform a malware into an evasive adversarial variant constrained by available
problem-space transformations.

"""

from black_box_attack import Sample
from collections import Counter
import timeit

from timeit import default_timer as timer

import copy
import numpy as np
import os
import scipy
import shutil
import ujson as json
import glob

import feature_extraction.drebin as drebin
import transformation.extraction as extraction
import transformation.inpatients as inpatients
from transformation import injection
import lib.utils as utils
from settings import config
from lib.utils import blue, green, cyan, magenta, yellow
from black_box_attack import label_virus_total as vt

import logging



import random
import pickle
from android_malware_with_n_gram import batch_disasseble, bytecode_extract,n_gram

from mamadroid import mamadroid, MaMaStat
"""
Hamid functions
"""
def loss_function(model,x_malware, x_manipulated,malware_detector):
    if malware_detector == "MaMaDroid":
        y_scores_malware = model.clf.predict_proba(x_malware)
        y_scores_adv_malware = model.clf.predict_proba(x_manipulated)
        y_scores_malware = y_scores_malware[0][0]
        y_scores_adv_malware = y_scores_adv_malware[0][0]
        print("y_scores_malware: ", y_scores_malware)
        print("y_scores_adv_malware: ", y_scores_adv_malware)
        loss = y_scores_adv_malware - y_scores_malware
    else:
        y_scores_malware = model.clf.decision_function(x_malware)
        y_scores_adv_malware = model.clf.decision_function(x_manipulated)  
        loss = y_scores_malware-y_scores_adv_malware
    
    
    y_pred_adv = model.clf.predict(x_manipulated)[0]
    return loss, y_pred_adv

def loss_function_for_hard_label(model,post_op_host, x_manipulated,malware_detector):
    rootdir = config['tmp_dir'] + "smalis"
    res, fullTopath = batch_disasseble.disassemble_adv(post_op_host, rootdir, 3000)   
    if res == 0:
        bytecode_extract.collect_adv(fullTopath,1,post_op_host)     
        loss = n_gram.extract_n_gram_adv(5, post_op_host) 
        print("hard-label-loss: " + str(loss))
        loss = utils.round_down(loss,1)
        print("hard-label-loss after round down: " + str(loss))
    else:
        loss = 0
    print("post_op_host: ",post_op_host)
    if malware_detector == "Drebin":
        y_pred_adv = model.clf.predict(x_manipulated)[0]
    elif malware_detector == "Kaspersky":
        no_detect,Kaspersky,_,_,_,_,_,_,_,_,_ = vt.report(post_op_host)
        y_pred_adv = bool(int(Kaspersky))
    elif malware_detector == "McAfee":
        no_detect,_,_,McAfee,_,_,_,_,_,_,_ = vt.report(post_op_host)
        y_pred_adv = bool(int(McAfee))
    elif malware_detector == "Microsoft":
        no_detect,_,_,_,Microsoft,_,_,_,_,_,_ = vt.report(post_op_host)
        y_pred_adv = bool(int(Microsoft))
    elif malware_detector == "ESET-NOD32":
        no_detect,_,_,_,_,_,_,ESETNOD32,_,_,_ = vt.report(post_op_host)
        y_pred_adv = bool(int(ESETNOD32))
    elif malware_detector == "Symantec":
        no_detect,_,Symantec,_,_,_,_,_,_,_,_ = vt.report(post_op_host)
        y_pred_adv = bool(int(Symantec))
    return loss, y_pred_adv,no_detect
    


def generate_adversarial_example(malware, action_set, q, increase_in_size, 
                                 model_inaccessible, hard_label, malware_detector):
    
    if malware_detector == "Kaspersky" and os.path.basename(malware) == "com.myproject.theme.oibikbhdfXEuIDflfdm.apk":
        q = 2
    if malware_detector == "ESET-NOD32" and os.path.basename(malware) == "com.ksdkxyv.fsdds.f.x.apk":
        q = 2
    k = 1
    app_name = os.path.basename(malware)
    percentage_increasing_size = 0
    number_of_features_adv_malware_per_query = list()
    number_of_api_calls_adv_malware_per_query = list()
    transformations = list()
    M_total = [] 
    increase_in_size_current = 0
    
    
    
    
    number_of_features_adv_malware = 0
    number_of_api_calls_adv_malware = 0
    
    print("malware: " + str(malware))
    utils.perform_logging_for_attack("malware: " + str(malware))
    logging.info(blue('Loading host malware...'))
    host = inpatients.Host.load(malware)    
    logging.info(green(f'Host {host.name} loaded!'))
    
    y_pred_adv = 1
    sampling_distribution = list(action_set.keys())
    result = 1    
    
    U = list(range(0,len(sampling_distribution)))
    M = []   
    malware_dict = drebin.get_features(malware)    
    no_malware_feature = len(malware_dict.keys()) 
    number_of_features_malware = no_malware_feature
    no_of_api_calls_malware = len([f for f in malware_dict.keys() if 'api_calls' in f or 'interesting_calls' in f])
    number_of_api_calls_malware = no_of_api_calls_malware
    
    print("number of malware features: " + str(no_malware_feature))
    utils.perform_logging_for_attack("number of malware features: " + str(no_malware_feature))
    no_adv_malware_feature = no_malware_feature
    number_of_features_adv_malware = no_adv_malware_feature
    
    feature_malware_keys = malware_dict.keys()
    feature_malware_no_api_call = [f for f in feature_malware_keys if 'api_calls' in f]
    print("no api calls in malware: " + str(len(feature_malware_no_api_call)))
    utils.perform_logging_for_attack("no api calls in malware: " + str(len(feature_malware_no_api_call)))
    
    malware_size = os.path.getsize(malware)
    print("malware size (byte): " + str(malware_size))
    utils.perform_logging_for_attack("malware size (byte): " + str(malware_size))
    
    if malware_detector == "MaMaDroid":        
        path = os.path.join(config['mamadroid'],'Features/Families/dataset_accessible_malware.p')    
        with open(path, 'rb') as f:
            apks_path_for_mamadroid = pickle.load(f)     
        apks_path_for_mamadroid.pop(0)  
     
        #x_malware_mamadroid = [item[1:] for item in apks_path_for_mamadroid if item[0].replace('.txt','.apk') == os.path.basename(malware)]
        x_malware_mamadroid = [item[1:] for item in apks_path_for_mamadroid if os.path.splitext(item[0])[0] + '.apk' == os.path.basename(malware)]
        print("x_malware_mamadroid: ", str(x_malware_mamadroid[0]))
        x_malware_mamadroid = x_malware_mamadroid[0]
        x_malware_mamadroid = np.array(x_malware_mamadroid)
        x_malware_mamadroid = x_malware_mamadroid.reshape(1,-1)
        y_pred_adv = model_inaccessible.clf.predict(x_malware_mamadroid)[0]
        decision_score = model_inaccessible.clf.predict_proba(x_malware_mamadroid)
        decision_score = decision_score[0][0]
        new_adv_dict = malware_dict
        L_best = 0 #model_inaccessible.clf.decision_function(x_malware)    
    
    elif malware_detector == "Drebin" or malware_detector == "SecSVM":    
        x_malware = model_inaccessible.dict_to_feature_vector(malware_dict) 
        y_pred_adv = model_inaccessible.clf.predict(x_malware)[0]       
        decision_score =  model_inaccessible.clf.decision_function(x_malware)
        new_adv_dict = malware_dict
        L_best = -0.01 #model_inaccessible.clf.decision_function(x_malware)  
    else:
        new_adv_dict = dict()
        if malware_detector == "Kaspersky":
            no_detect_best,Kaspersky,_,_,_,_,_,_,_,_,_ = vt.report(malware)
            y_pred_adv = bool(int(Kaspersky))
        elif malware_detector == "McAfee":
            no_detect_best,_,_,McAfee,_,_,_,_,_,_,_ = vt.report(malware)
            y_pred_adv = bool(int(McAfee))
        elif malware_detector == "Microsoft":
            no_detect_best,_,_,_,Microsoft,_,_,_,_,_,_ = vt.report(malware)
            y_pred_adv = bool(int(Microsoft))
        elif malware_detector == "ESET-NOD32":
            no_detect_best,_,_,_,_,_,_,ESETNOD32,_,_,_ = vt.report(malware)
            y_pred_adv = bool(int(ESETNOD32))
        elif malware_detector == "Symantec":
            no_detect_best,_,Symantec,_,_,_,_,_,_,_,_ = vt.report(malware)
            y_pred_adv = bool(int(Symantec))            
        L_best = 0  
    
    start = timer()
    number_of_query = 0    
       
    print("label malware: " +str(y_pred_adv))
    malware_label = y_pred_adv
    utils.perform_logging_for_attack("label malware: " +str(y_pred_adv))
    is_intact = 1
    is_try_to_inject = 0#This flag is used to show that at least one injection was done duting transplantation
    
    label_per_query = dict()
    modified_features_per_query = dict()
    
    cnt_size_check = 0
    cnt_injection_failed = 0
    while number_of_query < q and y_pred_adv == 1:      
        
        if cnt_size_check > 5 or cnt_injection_failed > 5:
            break
        U = [x for x in U if x not in M] #We should remove the features that have been already modified. Note they also includes side effect features
        result = 1
        
        print("len(U): " + str(len(U)))
        if len(U) == 0:
            break
        if len(U)>len(M):
            if len(U) > k:
                M = random.sample(U,k)
            else:
                M = U
        else:
            M = U
        
        for m in range(0,len(M)):
            M_total.append(M[m])            
        apks = []        
        for i in range(0,len(M_total)):
            #print("Tansformation No: ",i)
            if action_set.get(sampling_distribution[M_total[i]]) == None:
                 continue
            organ  = action_set[sampling_distribution[M_total[i]]]
            apks.append(organ.location)        
        
        utils.perform_logging_for_attack("sampling: " + str(M_total[i]))
        print("sampling - No: " + str(M_total[i]))
        print("sampling - Feature: " + str(sampling_distribution[M_total[i]]))
        
        utils.perform_logging_for_attack("start tranfromation - no of query: %d - app: %s" % (number_of_query,app_name))
        print("start tranfromation - no of query: %d - app: %s" % (number_of_query,app_name))
        result, post_op_host, side_effects = injection.transplant_organs(host, apks)
        print("end tranfromation - no of query: %d - app: %s - result: %d - cnt_injection_failed: %d" % (number_of_query,app_name,result,cnt_injection_failed))
        utils.perform_logging_for_attack("end tranfromation - no of query: %d - app: %s" % (number_of_query,app_name))
        
        if result == 1: 
            cnt_injection_failed += 1
            #modified_features_per_query[number_of_query] = no_adv_malware_feature - no_malware_feature
            for m in range(0,len(M)):
                M_total.remove(M[m])  
            continue
        cnt_injection_failed = 0 #reset it one one organ inject successfuly
        is_try_to_inject = 1 #This flag show that at least one injection was done
        new_adv_dict_temp = new_adv_dict
        if malware_detector == "MaMaDroid" or malware_detector == "Drebin" or malware_detector == "SecSVM":
            new_adv_dict = drebin.get_features(post_op_host) 
        else:
            new_adv_dict = dict()
        no_adv_malware_feature = len(new_adv_dict.keys())
        no_of_api_calls_adv_malware = len([f for f in new_adv_dict.keys() if 'api_calls' in f or 'interesting_calls' in f])
        
        print("number of adv malware features: " + str(no_adv_malware_feature))
        utils.perform_logging_for_attack("number of adv malware features: " + str(no_adv_malware_feature))
        
        feature_adv_malware_keys = new_adv_dict.keys()
        feature_adv_malware_no_api_call = [f for f in feature_adv_malware_keys if 'api_calls' in f]
        print("no api calls in malware: " + str(len(feature_adv_malware_no_api_call)))
        utils.perform_logging_for_attack("no api calls in malware: " + str(len(feature_adv_malware_no_api_call)))
        
        adv_malware_size = os.path.getsize(post_op_host)
        print("adv_malware size (byte): " + str(adv_malware_size))
        utils.perform_logging_for_attack("adv_malware size (byte): " + str(adv_malware_size))
        
        increase_in_size_current = (adv_malware_size - malware_size)/malware_size
        print("increase_in_size_current size (%): " + str(increase_in_size_current))
        utils.perform_logging_for_attack("increase_in_size_current size (%): " + str(increase_in_size_current))
        
        print("cnt_size_check: %s - Check increase size: %s" % (cnt_size_check,str(float(increase_in_size_current) <= float(increase_in_size))))
        if (float(increase_in_size_current)> 0 and float(increase_in_size_current) <= float(increase_in_size)):                       
            #Any way we should consider all features
            #new_adv_dict = soot_filter(host.features, new_adv_dict, side_effects)
            cnt_size_check = 0 #reset it once the size is ok
            if malware_detector == "MaMaDroid":
                try:
                    #db = "sample_" + os.path.basename(malware).replace('.apk','').replace('.','_')
                    db = "sample_" + os.path.splitext(os.path.basename(malware))[0].replace('.','_')
                    mamadroid.api_sequence_extraction([post_op_host],db)
                    _app_dir = config['mamadroid']
                    no_finished_apps = len(os.listdir(os.path.join(_app_dir,'graphs',db)))
                    if no_finished_apps == 0: 
                        print("Remove transformation because of failing in creating api call graph")
                        files = glob.glob(host.tmpdname +"/postop/*")
                        for f in files:
                            os.remove(f)                        
                        for m in range(0,len(M)):
                            M_total.remove(M[m])  
                        continue
                    dbs = list()
                    dbs.append(db)
                    MaMaStat.feature_extraction_markov_chain(dbs)
                    path = os.path.join(config['mamadroid'],"Features/Families/" + db + ".p")    
                    with open(path, 'rb') as f:
                        apks_path_for_mamadroid = pickle.load(f)     
                    apks_path_for_mamadroid.pop(0)  
                    x_manipulated_mamadroid = [item[1:] for item in apks_path_for_mamadroid]
                    print("x_manipulated_mamadroid: ", str(x_manipulated_mamadroid[0]))
                    x_manipulated_mamadroid = x_manipulated_mamadroid[0]  
                    x_manipulated_mamadroid = np.array(x_manipulated_mamadroid)
                    x_manipulated_mamadroid = x_manipulated_mamadroid.reshape(1,-1)
                    _app_dir = config['mamadroid']
                    os.remove(_app_dir + "/Features/Families/" + db +'.p')
                    shutil.rmtree(_app_dir + "/graphs/" + db)
                    shutil.rmtree(_app_dir + "/package/" + db)
                    shutil.rmtree(_app_dir + "/family/" + db)
                    shutil.rmtree(_app_dir + "/class/" + db)                
                    
                    #shutil.rmtree(_app_dir + "/Features/Packages" + db +'.p')
                except Exception as e:
                    print("exception: ", e)
                    x_manipulated_mamadroid = x_malware_mamadroid
            elif malware_detector == "Drebin" or malware_detector == "SecSVM":
                x_manipulated = model_inaccessible.dict_to_feature_vector(new_adv_dict) 
            else:
                x_manipulated = ""
            
            
            if hard_label == False:
                if malware_detector != "MaMaDroid":
                    L, y_pred_adv = loss_function(model_inaccessible,x_malware,x_manipulated,malware_detector)
                else:
                    L, y_pred_adv = loss_function(model_inaccessible,x_malware_mamadroid,x_manipulated_mamadroid,malware_detector)
            else:
                L, y_pred_adv,no_detect = loss_function_for_hard_label(model_inaccessible,post_op_host,x_manipulated,malware_detector)
           
            if malware_detector != "Drebin" and malware_detector != "SecSVM" and malware_detector != "MaMaDroid":
                if no_detect > no_detect_best:
                    print("no_detect > no_detect_previou: True")
                    L = 0
                else:
                    no_detect_best = no_detect
                    
            print("current loss: " + str(L))
            utils.perform_logging_for_attack("current loss: " + str(L))
            number_of_query += 1
            
            
            label_per_query[number_of_query] = y_pred_adv        
            
            if hard_label == False:
                if malware_detector != "MaMaDroid":
                    loss_cmp = L > L_best
                else:
                    loss_cmp = L >= L_best
            else:
                loss_cmp = L >= L_best
                
            print("loss_cmp: "+str(loss_cmp))
            if loss_cmp:
                modified_features_per_query[number_of_query] = no_adv_malware_feature - no_malware_feature
                is_intact = 0
                L_best = L              
                number_of_features_adv_malware_per_query.append(no_adv_malware_feature)
                number_of_api_calls_adv_malware_per_query.append(no_of_api_calls_adv_malware)
            else:
                if number_of_query == 1:
                    modified_features_per_query[number_of_query] = no_adv_malware_feature - no_malware_feature
                    
                    number_of_features_adv_malware_per_query.append(no_malware_feature)
                    number_of_api_calls_adv_malware_per_query.append(no_of_api_calls_malware)
                    
                    
                else:
                    modified_features_per_query[number_of_query] = modified_features_per_query[number_of_query-1]
                    
                    length = len(number_of_features_adv_malware_per_query)
                    number_of_features_adv_malware_per_query.append(number_of_features_adv_malware_per_query[length-1])
                    length = len(number_of_api_calls_adv_malware_per_query)
                    number_of_api_calls_adv_malware_per_query.append(number_of_api_calls_adv_malware_per_query[length-1])
                for m in range(0,len(M)):
                    M_total.remove(M[m])  
        
        
            files = glob.glob(host.tmpdname +"/postop/*")
            if y_pred_adv == 1:
                for f in files:
                    os.remove(f)
            
            utils.perform_logging_for_attack("number of query: " + str(number_of_query) + 
                  " - current loss: " + str(L) + " - best loss: " + str(L_best) +" - best actions: " + str(M_total))
            print("number of query: " + str(number_of_query) + 
                  " - current loss: " + str(L) + " - best loss: " + str(L_best) +" - best actions: " + str(M_total))
        else:
            cnt_size_check += 1
            new_adv_dict = new_adv_dict_temp # roll back new_adv_dict
            files = glob.glob(host.tmpdname +"/postop/*")
            for f in files:
                os.remove(f)
            for m in range(0,len(M)):
                M_total.remove(M[m])  
            
    

    
    if malware_detector == "Drebin" or malware_detector == "SecSVM":    
        if is_intact == 0:        
            adv_malware_label = model_inaccessible.clf.predict(x_manipulated)[0]  
            adv_decision_score = model_inaccessible.clf.decision_function(x_manipulated)[0]
        else:
            adv_malware_label = model_inaccessible.clf.predict(x_malware)[0]
            adv_decision_score = model_inaccessible.clf.decision_function(x_malware)[0]
    elif malware_detector == "MaMaDroid":
        if is_intact == 0:                
            adv_malware_label = model_inaccessible.clf.predict(x_manipulated_mamadroid)[0]   
            adv_decision_score = model_inaccessible.clf.predict_proba(x_manipulated_mamadroid)
        else:
            adv_malware_label = model_inaccessible.clf.predict(x_malware_mamadroid)[0]
            adv_decision_score = model_inaccessible.clf.predict_proba(x_malware_mamadroid)
    else:
        if is_intact == 0:
            if os.path.exists(post_op_host) == False:
                adv_malware_label = 1
            else:
                if malware_detector == "Kaspersky":
                    _,Kaspersky,_,_,_,_,_,_,_,_,_ = vt.report(post_op_host)
                    adv_malware_label = bool(int(Kaspersky))
                elif malware_detector == "McAfee":
                    _,_,_,McAfee,_,_,_,_,_,_,_ = vt.report(post_op_host)
                    adv_malware_label = bool(int(McAfee))
                elif malware_detector == "Microsoft":
                    _,_,_,_,Microsoft,_,_,_,_,_,_ = vt.report(post_op_host)
                    adv_malware_label = bool(int(Microsoft))
                elif malware_detector == "ESET-NOD32":
                    _,_,_,_,_,_,_,ESETNOD32,_,_,_ = vt.report(post_op_host)
                    adv_malware_label = bool(int(ESETNOD32))
                elif malware_detector == "Symantec":
                    _,_,Symantec,_,_,_,_,_,_,_,_ = vt.report(post_op_host)
                    adv_malware_label = bool(int(Symantec))
        else:
            adv_malware_label = 1
        
    dest = os.path.join(host.results_dir + "/postop", host.name)
    if y_pred_adv == 0:
        shutil.copyfile(post_op_host,dest)
    else:
        host_path = os.path.join(host.tmpdname, host.name)
        shutil.copyfile(host_path,dest)
    shutil.rmtree(host.tmpdname)
        
    
    
    
    number_of_queries = number_of_query
    
    if adv_malware_label == 0 :
        percentage_increasing_size = increase_in_size_current 
        transformations = M_total
        number_of_features_adv_malware = no_adv_malware_feature
        number_of_api_calls_adv_malware = no_of_api_calls_adv_malware
        
    
    intact_due_to_soot_error = 1 - is_try_to_inject
    end = timer()
    execution_time = end - start
    print("execution_time: ", execution_time)
    classified_with_hard_label = hard_label
    apk = Sample.APK(app_name,malware_label, adv_malware_label, 
                 number_of_queries, percentage_increasing_size, 
                 number_of_features_malware,number_of_features_adv_malware,
                 number_of_features_adv_malware_per_query,
                 number_of_api_calls_malware,number_of_api_calls_adv_malware,
                 number_of_api_calls_adv_malware_per_query, transformations,
                 intact_due_to_soot_error,execution_time,classified_with_hard_label)
    
    return apk


def create_adversarial_sample(malware, action_set, q, increase_in_size, k, alpha, model_inaccessible, hard_label, malware_detector):
    '''
    Parameters:
        q: number of queries
        k: number of perturbation (sparsity)
        alpha: piecewise constant schedule
    '''
    print("malware: " + str(malware))
    utils.perform_logging_for_attack("malware: " + str(malware))
    logging.info(blue('Loading host malware...'))
    host = inpatients.Host.load(malware)    
    logging.info(green(f'Host {host.name} loaded!'))
    
    y_pred_adv = 1
    sampling_distribution = list(action_set.keys())
    result = 1    
    
    U = list(range(0,len(sampling_distribution)))
    M = []   
    malware_dict = drebin.get_features(malware)    
    no_malware_feature = len(malware_dict.keys())  
    print("number of malware features: " + str(no_malware_feature))
    utils.perform_logging_for_attack("number of malware features: " + str(no_malware_feature))
    no_adv_malware_feature = no_malware_feature
    
    feature_malware_keys = malware_dict.keys()
    feature_malware_no_api_call = [f for f in feature_malware_keys if 'api_calls' in f]
    print("no api calls in malware: " + str(len(feature_malware_no_api_call)))
    utils.perform_logging_for_attack("no api calls in malware: " + str(len(feature_malware_no_api_call)))
    
    malware_size = os.path.getsize(malware)
    print("malware size (byte): " + str(malware_size))
    utils.perform_logging_for_attack("malware size (byte): " + str(malware_size))
    
    if malware_detector != "Drebin":        
        path = os.path.join(config['mamadroid'],'Features/Families/DB_test.p')    
        with open(path, 'rb') as f:
            apks_path_for_mamadroid = pickle.load(f)     
        apks_path_for_mamadroid.pop(0)  
     
        #x_malware_mamadroid = [item[1:] for item in apks_path_for_mamadroid if item[0].replace('.txt','.apk') == os.path.basename(malware)]
        x_malware_mamadroid = [item[1:] for item in apks_path_for_mamadroid if os.path.splitext(item[0])[0] + '.apk' == os.path.basename(malware)]
        print("x_malware_mamadroid: ", str(x_malware_mamadroid[0]))
        x_malware_mamadroid = x_malware_mamadroid[0]
        x_malware_mamadroid = np.array(x_malware_mamadroid)
        x_malware_mamadroid = x_malware_mamadroid.reshape(1,-1)
        y_pred_adv = model_inaccessible.clf.predict(x_malware_mamadroid)[0]
        decision_score = model_inaccessible.clf.predict_proba(x_malware_mamadroid)
        decision_score = decision_score[0][0]
        new_adv_dict = malware_dict
        L_best = 0 #model_inaccessible.clf.decision_function(x_malware)    
    
    else:    
        x_malware = model_inaccessible.dict_to_feature_vector(malware_dict) 
        y_pred_adv = model_inaccessible.clf.predict(x_malware)        
        decision_score =  model_inaccessible.clf.decision_function(x_malware)
        new_adv_dict = malware_dict
        L_best = -0.01 #model_inaccessible.clf.decision_function(x_malware)    
    
    
    number_of_query = 0    
    M_total = []    
    print("label malware: " +str(y_pred_adv))
    utils.perform_logging_for_attack("label malware: " +str(y_pred_adv))
    is_intact = 1
    is_try_to_inject = 0#This flag is used to show that at least one injection was done duting transplantation
    
    label_per_query = dict()
    modified_features_per_query = dict()
    
    while number_of_query < q and y_pred_adav == 1:       
        '''
        side_effects_vector = model_inaccessible.dict_to_feature_vector(side_effects) 
        side_effects_features = [i for i, val in side_effects_vector if val != 0]
        modified_features = list(set(M)|set(side_effects_features))
        '''
        #We should remove the features that have been already modified. Note they also includes side effect features
        #print("U: " + str(U))
        
        # I comment it for checking new idea because injecting organs is important not features
        '''        
        U_temp = U.copy()
        for f in range(0,len(U_temp)):
            if sampling_distribution[U_temp[f]] in new_adv_dict.keys():
                U.remove(U_temp[f])               
        '''
                
        U = [x for x in U if x not in M] #We should remove the features that have been already modified. Note they also includes side effect features
        result = 1
        
        print("len(U): " + str(len(U)))
        if len(U) == 0:
            break
        if len(U)>len(M):
            if len(U) > k:
                M = random.sample(U,k)
            else:
                M = U
        else:
            M = U
        
        for m in range(0,len(M)):
            M_total.append(M[m])            
        apks = []        
        for i in range(0,len(M_total)):
            #print("Tansformation No: ",i)
            if action_set.get(sampling_distribution[M_total[i]]) == None:
                 continue
            organ  = action_set[sampling_distribution[M_total[i]]]
            apks.append(organ.location)            
        
        '''
        files = glob.glob(host.tmpdname +"/postop/*")
        for f in files:
            os.remove(f)
        '''
        
        
        utils.perform_logging_for_attack("sampling: " + str(M_total[i]))
        print("sampling - No: " + str(M_total[i]))
        print("sampling - Feature: " + str(sampling_distribution[M_total[i]]))
        
        utils.perform_logging_for_attack("start tranfromation: " + str(number_of_query))
        print("start tranfromation: " + str(number_of_query))
        result, post_op_host, side_effects = injection.transplant_organs(host, apks)
        print("end tranfromation - result: " + str(result))
        utils.perform_logging_for_attack("end tranfromation - result: " + str(result))
        
        if result == 1:    
            #modified_features_per_query[number_of_query] = no_adv_malware_feature - no_malware_feature
            for m in range(0,len(M)):
                M_total.remove(M[m])  
            continue
        is_try_to_inject = 1 #This flag show that at least one injection was done
        new_adv_dict_temp = new_adv_dict
        new_adv_dict = drebin.get_features(post_op_host)   
        no_adv_malware_feature = len(new_adv_dict.keys())
        print("number of adv malware features: " + str(no_adv_malware_feature))
        utils.perform_logging_for_attack("number of adv malware features: " + str(no_adv_malware_feature))
        
        feature_adv_malware_keys = new_adv_dict.keys()
        feature_adv_malware_no_api_call = [f for f in feature_adv_malware_keys if 'api_calls' in f]
        print("no api calls in malware: " + str(len(feature_adv_malware_no_api_call)))
        utils.perform_logging_for_attack("no api calls in malware: " + str(len(feature_adv_malware_no_api_call)))
        
        adv_malware_size = os.path.getsize(post_op_host)
        print("adv_malware size (byte): " + str(adv_malware_size))
        utils.perform_logging_for_attack("adv_malware size (byte): " + str(adv_malware_size))
        
        increase_in_size_current = (adv_malware_size - malware_size)/malware_size
        print("increase_in_size_current size (%): " + str(increase_in_size_current))
        utils.perform_logging_for_attack("increase_in_size_current size (%): " + str(increase_in_size_current))
        
        print("Check increase size: " + str(float(increase_in_size_current) <= float(increase_in_size)))
        if (float(increase_in_size_current) <= float(increase_in_size)):
        
            #Any way we should consider all features
            #new_adv_dict = soot_filter(host.features, new_adv_dict, side_effects)
            
            if malware_detector != "Drebin":
                try:
                    #db = "sample_" + os.path.basename(malware).replace('.apk','').replace('.','_')                    
                    db = "sample_" + os.path.splitext(os.path.basename(malware))[0].replace('.','_')
                    mamadroid.api_sequence_extraction([post_op_host],db)
                    dbs = list()
                    dbs.append(db)
                    MaMaStat.feature_extraction_markov_chain(dbs)
                    path = os.path.join(config['mamadroid'],"Features/Families/" + db + ".p")    
                    with open(path, 'rb') as f:
                        apks_path_for_mamadroid = pickle.load(f)     
                    apks_path_for_mamadroid.pop(0)  
                    x_manipulated_mamadroid = [item[1:] for item in apks_path_for_mamadroid]
                    print("x_manipulated_mamadroid: ", str(x_manipulated_mamadroid[0]))
                    x_manipulated_mamadroid = x_manipulated_mamadroid[0]  
                    x_manipulated_mamadroid = np.array(x_manipulated_mamadroid)
                    x_manipulated_mamadroid = x_manipulated_mamadroid.reshape(1,-1)
                    _app_dir = config['mamadroid']
                    shutil.rmtree(_app_dir + "/graphs/" + db)
                    shutil.rmtree(_app_dir + "/package/" + db)
                    shutil.rmtree(_app_dir + "/family/" + db)
                    shutil.rmtree(_app_dir + "/class/" + db)                
                    os.remove(_app_dir + "/Features/Families/" + db +'.p')
                    #shutil.rmtree(_app_dir + "/Features/Packages" + db +'.p')
                except:
                    x_manipulated_mamadroid = x_malware_mamadroid
            else:
                x_manipulated = model_inaccessible.dict_to_feature_vector(new_adv_dict) 
            
            
            if hard_label == False:
                if malware_detector == "Drebin":
                    L, y_pred_adv = loss_function(model_inaccessible,x_malware,x_manipulated,malware_detector)
                else:
                    L, y_pred_adv = loss_function(model_inaccessible,x_malware_mamadroid,x_manipulated_mamadroid,malware_detector)
            else:
                L, y_pred_adv = loss_function_for_hard_label(model_inaccessible,post_op_host,x_manipulated,malware_detector)
           
            print("current loss: " + str(L))
            utils.perform_logging_for_attack("current loss: " + str(L))
            number_of_query += 1
            
            label_per_query[number_of_query] = y_pred_adv        
            
            if hard_label == False:
                loss_cmp = L > L_best
            else:
                loss_cmp = L >= L_best
                
            print("loss_cmp: "+str(loss_cmp))
            if loss_cmp:
                modified_features_per_query[number_of_query] = no_adv_malware_feature - no_malware_feature
                is_intact = 0
                L_best = L
                '''
                host_path = os.path.join(host.tmpdname, host.name)
                os.remove(host_path)
                shutil.copy(post_op_host, host.tmpdname)
                '''
            else:
                if number_of_query == 1:
                    modified_features_per_query[number_of_query] = no_adv_malware_feature - no_malware_feature
                else:
                    modified_features_per_query[number_of_query] = modified_features_per_query[number_of_query-1]
                for m in range(0,len(M)):
                    M_total.remove(M[m])  
        
        
            files = glob.glob(host.tmpdname +"/postop/*")
            if y_pred_adv == 1:
                for f in files:
                    os.remove(f)
            
            utils.perform_logging_for_attack("number of query: " + str(number_of_query) + 
                  " - current loss: " + str(L) + " - best loss: " + str(L_best) +" - best actions: " + str(M_total))
            print("number of query: " + str(number_of_query) + 
                  " - current loss: " + str(L) + " - best loss: " + str(L_best) +" - best actions: " + str(M_total))
        else:
            new_adv_dict = new_adv_dict_temp # roll back new_adv_dict
            files = glob.glob(host.tmpdname +"/postop/*")
            for f in files:
                os.remove(f)
            for m in range(0,len(M)):
                M_total.remove(M[m])  
            
    
    dest = os.path.join(host.results_dir + "/postop", host.name)
    if y_pred_adv == 0:
        shutil.copyfile(post_op_host,dest)
    else:
        host_path = os.path.join(host.tmpdname, host.name)
        shutil.copyfile(host_path,dest)
    shutil.rmtree(host.tmpdname)
    
    if malware_detector == "Drebin":    
        if is_intact == 0:        
            adv_malware_label = model_inaccessible.clf.predict(x_manipulated)   
            adv_decision_score = model_inaccessible.clf.decision_function(x_manipulated)                    
        else:
            adv_malware_label = model_inaccessible.clf.predict(x_malware)   
            adv_decision_score = model_inaccessible.clf.decision_function(x_malware)
    else:
        if is_intact == 0:                
            adv_malware_label = model_inaccessible.clf.predict(x_manipulated_mamadroid)   
            adv_decision_score = model_inaccessible.clf.predict_proba(x_manipulated_mamadroid)                  
        else:
            adv_malware_label = model_inaccessible.clf.predict(x_malware_mamadroid)   
            adv_decision_score = model_inaccessible.clf.predict_proba(x_malware_mamadroid)
    return label_per_query,modified_features_per_query,adv_malware_label,decision_score,adv_decision_score, number_of_query,no_malware_feature,no_adv_malware_feature,is_intact,is_try_to_inject
    
         
    
        
    '''
    try:
        problem_space_transplant(record, model, output_dir)
        successful = True
    except evasion.RetryableFailure as e:
        tries -= 1

        if tries > 0:
            logging.warning(red('Encountered a random error, retrying...'))
        else:
            logging.error(red('Ran out of tries :O Logging error...'))
            utils.log_failure(record, str(e), output_dir)
    except Exception as e:
        msg = f'Process fell over with: [{e}]: \n{traceback.format_exc()}'
        utils.log_failure(record, msg, output_dir)
        return e
    '''
    




def make_evasive(malware, model, orgs, margin, output_dir):
    """Generate an adversarial feature vector and patient record based on available organs.

    Two important outputs are generated by this function:

        * Adversarial feature vector:
            A mutated feature vector that will be misclassified by the target model. This feature vector
            is constrained by the available features (and associated side effect features) and acts as an
            estimation to the features induced by the end-to-end problem-space transformation.
        * Patient record:
            A record of the host and organs expected to cause misclassification. These records are used to
            later on to tell the transplantation functions which physical mutations to perform.

    Args:
        malware (str): The path to the malware to be made evasive.
        model (SVMModel): The model to target.
        orgs (list): List of harvested `Organs` ready for transplant.
        margin (float): The confidence margin to use during the attack.
        output_dir (str): The root of the output directory in which to dump generated artifacts.

    """
    logging.info(blue('Loading host malware...'))
    host = inpatients.Host.load(malware)
    logging.info(green(f'Host {host.name} loaded!'))

    # Setup output file paths
    records_dir = os.path.join(output_dir, 'records')
    record_name = f'{host.name}.record.json'

    features_dir = os.path.join(output_dir, 'adv-features')
    features_name = f'{host.name}.adv.json'

    # Check if adv feature (and record - implicit) has already been created
    if os.path.exists(os.path.join(features_dir, features_name)):
        return

    # Calculate the minimum perturbation needed for misclassification
    X_initial_vector = model.dict_to_feature_vector(host.features)

    initial_score = model.clf.decision_function(X_initial_vector)[0]
    predicted_class = model.clf.predict(X_initial_vector)

    if predicted_class == 0:
        msg = f'Initial target {host.name} is not predicted as malware! (weird)'
        raise Exception(msg)

    logging.info(blue('Calculating target score and target perturbation...'))
    target_perturbation = np.abs(initial_score - -margin)
    logging.info(f'{initial_score} - {target_perturbation} = -{margin}')

    # Mutate and save feature vector based on available organs

    logging.info(blue('Generating viable adversarial vector...'))

    orgs_to_consider = copy.deepcopy(orgs)
    l1_original = sum(host.features.values())
    to_inject = {}

    def confidence_too_low(x):
        score = model.clf.decision_function(model.dict_to_feature_vector(x))[0]
        return score > -margin

    while confidence_too_low(host.features):
        vals = [extraction.contributions(x, model.weight_dict, host) for x in orgs_to_consider]

        # Sort organs by largest (negative) contribution
        sorted_orgs = [None] * len(orgs_to_consider)
        for i, j in enumerate(np.argsort(vals)):
            sorted_orgs[i] = orgs_to_consider[j]
        orgs_to_consider = sorted_orgs

        next_best = orgs_to_consider.pop(0)

        to_inject[next_best.feature] = next_best
        host.features.update(next_best.feature_dict)

    l1_adv = sum(host.features.values())

    new_vector = model.dict_to_feature_vector(host.features)
    new_score = model.clf.decision_function(new_vector)[0]
    logging.info(yellow(f'New score: {new_score} (< -{margin})'))

    utils.dump_json(host.features, features_dir, features_name)

    # Save patient record

    patient_record = {
        'host': malware,
        'organs': [org.location for org in to_inject.values()],
        'score': float(initial_score),
        'margin': margin,
        'target_perturbation': float(target_perturbation),
        'organ_contribution': float(new_score - initial_score),
        'distortion_l1': l1_adv - l1_original
    }

    patient_record.update(get_counts(host.features))
    utils.dump_json(patient_record, records_dir, record_name)


def problem_space_transplant(record, model, output_dir):
    """Perform transplant described in patient record.

    Args:
        record (str): The path to the patient record detailing which organs are to be transplanted.
        model (SVMModel): The target model.
        output_dir (str): The root of the output directory in which to dump generated artifacts.

    """
    start = timer()

    with open(record, 'r') as f:
        record = json.load(f)

    # Load malware host
    host = inpatients.Host.load(record['host'])
    logging.info(green(f'Host {host.name} ready for operation!'))

    # Load organs
    to_inject = {}
    for filename in record['organs']:
        with open(filename + '/organ.p', 'rb') as f:
            o = pickle.load(f)
        to_inject[o.feature] = o

    X_original = model.dict_to_feature_vector(host.features)

    # Calculate surplus permissions
    surplus_permissions = set()
    for organ in to_inject.values():
        surplus_permissions.update(organ.permissions)
    surplus_permissions -= set(host.permissions)

    # Create dictionary to store ongoing statistics
    results = {}

    # Necessary features are known and extracted, perform inverse mapping
    logging.debug(green('Synthesizing adversarial evader...'))
    logging.info(green('Adding the following features:'))
    logging.info(green('\n' + '\n'.join(to_inject.keys())))
    logging.info(yellow('Including the following side-effects:'))
    side_effects = set()
    for organ in to_inject.values():
        organ_effects = {x for x in organ.feature_dict.keys()
                         if x != organ.feature}
        side_effects.update(organ_effects)
    logging.info(yellow('\n' + pformat(side_effects)))

    # These permissions are the ones needed for the new organs
    # They'll get added to the host manifest by the injector
    perm_file = os.path.join(host.tmpdname, 'permissions.txt')

    logging.info(
        'Injection requires ' + yellow(len(surplus_permissions)) + ' surplus permission(s): ' +
        yellow(surplus_permissions))
    logging.info(f'Writing to perm_file: {perm_file}...')

    with open(perm_file, "wt") as f:
        for p in surplus_permissions:
            splits = p.split("::")[1].replace("_", ".").split(".")
            if len(splits) == 3:
                tmp_p = p.split("::")[1].replace("_", ".")
            elif len(splits) == 4:
                tmp_p = splits[0] + "." + splits[1] + "." + \
                        splits[2] + "_" + splits[3]
            elif len(splits) == 5:
                tmp_p = splits[0] + "." + splits[1] + "." + \
                        splits[2] + "_" + splits[3] + "_" + \
                        splits[4]
            else:
                tmp_p = ''
            f.write(tmp_p)

    # Create the string for input to the injector pointing to the single gadget folders
    apks = ','.join([o.location for o in to_inject.values()])
    logging.debug(f'Final organs to inplant: {apks}')

    # Move files into a working directory and perform injection
    now = time.time()
    # perm_file = perm_file if len(surplus_permissions) > 0 else None
    post_op_host, final_avg_cc, classes_final = transplant(host, apks, perm_file)
    post = time.time()

    results['time_injection'] = int(post - now)

    # Handle error results
    if 'error' in post_op_host:
        msg = f"Error occurred during injection {post_op_host}"
        shutil.rmtree(host.tmpdname)
        raise RetryableFailure(msg)

    elif 'EXCEPTION' in post_op_host:
        logging.debug(" : " + post_op_host)
        logging.debug("Something went wrong during injection, see error.\n")
        if 'SootUtility.initSoot' in post_op_host:
            logging.debug("Soot exception for reading app")

        shutil.rmtree(host.tmpdname)
        msg = "Something went wrong during injection, see error above."
        raise Exception(msg)

    # Resign the modified APK (will overwrite the unsigned one)
    resign(post_op_host)
    logging.debug("Final apk signed")

    # Verify the features of the modified APK
    logging.debug('Verifying adversarial features...')
    new_adv_dict = drebin.get_features(post_op_host)
    new_adv_dict = soot_filter(host.features, new_adv_dict, side_effects)

    X_new_adv = model.dict_to_feature_vector(new_adv_dict)

    # X | Verify output prediction
    score = model.clf.decision_function(X_new_adv)[0]
    out = model.clf.predict(X_new_adv)[0]
    logging.debug('Final score: {}'.format(score))
    logging.debug('Final class prediction {}'.format(out))

    if out != 0:
        msg = f'Generated program not predicted as malware'
        raise RetryableFailure(msg)

    intended_features = set(to_inject.keys())
    obtained_features = set(new_adv_dict.keys())

    if all(x in obtained_features for x in intended_features):
        ret_message = "All intended features are present!"
        results['status'] = 'Success'
        logging.info(green(ret_message))
    else:
        ret_message = "Something went wrong, couldn't find all the features."
        total_time = utils.seconds_to_time(timer() - start)
        print('Time taken: {}'.format(total_time))
        raise RetryableFailure(ret_message)

    # Compute and output results/statistics

    size_final = os.path.getsize(post_op_host)
    end = timer()

    total_time = end - start

    X_ori_arr = X_original.toarray()[0]
    X_adv_arr = X_new_adv.toarray()[0]

    norm = scipy.linalg.norm
    distortion_l0 = abs(norm(X_ori_arr, 0) - norm(X_adv_arr, 0))
    distortion_l1 = abs(norm(X_ori_arr, 1) - norm(X_adv_arr, 1))
    distortion_l2 = abs(norm(X_ori_arr, 2) - norm(X_adv_arr, 2))
    distortion_linf = abs(norm(X_ori_arr, np.inf) - norm(X_adv_arr, np.inf))

    results['distortion_l0'] = distortion_l0
    results['distortion_l1'] = distortion_l1
    results['distortion_l2'] = distortion_l2
    results['distortion_linf'] = distortion_linf

    harvest_times = [o.extraction_time for o in to_inject.values()]

    results['post_op_host'] = post_op_host
    results['feature_stats_start'] = get_counts(host.features)
    results['feature_stats_final'] = get_counts(new_adv_dict)
    results['cc_start'] = host.avg_cc
    results['cc_final'] = final_avg_cc
    results['cc_difference'] = final_avg_cc - host.avg_cc
    results['classes_start'] = len(host.classes)
    results['classes_final'] = classes_final
    results['classes_difference'] = classes_final - len(host.classes)
    results['size_start'] = host.size
    results['size_final'] = size_final
    results['size_difference'] = size_final - host.size
    results['time_start'] = start
    results['time_end'] = end
    results['time_taken'] = total_time
    results['time_organ_extractions'] = harvest_times
    results['time_taken_with_harvesting'] = total_time + sum(harvest_times)

    report_path = os.path.join(output_dir, 'success', f'report-{host.name}.json')
    logging.info(f'Writing report to {report_path}')
    with open(report_path, 'wt') as f:
        json.dump(results, f, indent=2)

    # If a previous attempt had failed, remove error log
    failure_path = os.path.join(output_dir, 'failure', f'{host.name}.txt')
    if os.path.exists(failure_path):
        os.remove(failure_path)

    # Move post op from temp folder to output dir
    shutil.move(post_op_host, os.path.join(output_dir, 'postop', host.name + '.adv'))

    logging.info(blue('Time taken: {}'.format(utils.seconds_to_time(total_time))))
    logging.info(blue('Final size is  {} bytes - size increased by {} bytes'.format(
        size_final, size_final - host.size)))
    logging.info(blue('Final CC of the malware {} - CC difference {} '.format(
        final_avg_cc, final_avg_cc - host.avg_cc)))
    return





def resign(app_path):
    """Resign the apk."""
    utils.run_java_component(config['resigner'], ['--overwrite', '-a', app_path])

def get_counts(d):
    """Count features aggregated by type."""
    counter = Counter([x.split('::')[0] for x in d.keys()])
    try:
        del counter['_id']
        del counter['sha256']
    except KeyError:
        pass

    keys = ['intents', 'activities', 'providers', 'urls', 'interesting_calls',
            'api_permissions', 'app_permissions', 'api_calls', 's_and_r']

    return {k: counter.get(k, 0) for k in keys}


def soot_filter(X_original, X_generated, side_effects):
    """Remove erroneous features caused by Soot libraries.

    A bug in our version of Soot means that some additional libraries are added to the app
    even if they're explicitly blacklisted. The exact libraries will depend on your version of
    Soot and Java classpath.

    Here we filter out any features that were not present in either the original malware or any
    of the injected organs as these have been added erroneously by Soot.

    Args:
        X_original: The original malware features.
        X_generated: The generated adversarial malware object.
        side_effects: The set of side effect features that were added.

    Returns:
        Modified X_generated with erroneous features removed.

    """
    added_by_soot = {
        'api_calls::android/media/AudioRecord',
        'api_calls::android/telephony/TelephonyManager;->getSubscriberId',
        'api_calls::java/net/DatagramSocket',
        'api_calls::java/net/MulticastSocket',
        'api_calls::java/net/NetworkInterface',
        'api_permissions::android_permission_READ_PHONE_STATE',
        'api_permissions::android_permission_RECORD_AUDIO',
        'interesting_calls::getCellLocation',
        'interesting_calls::getCellSignalStrength',
        'interesting_calls::getDeviceId',
        'interesting_calls::getNetworkCountryIso',
        'interesting_calls::getSimCountryIso',
        'interesting_calls::getSubscriberId',
        'interesting_calls::getWifiState',
        'interesting_calls::sendSMS',
        'interesting_calls::setWifiEnabled',
        'urls::http://apache_org/xml/features/validation/dynamic',
        'urls::http://apache_org/xml/features/validation/schema',
        'urls::http://java_sun_com/jaxp/xpath/dom',
        'urls::http://javax_xml_XMLConstants/feature/secure-processing',
        'urls::http://javax_xml_transform_dom_DOMResult/feature',
        'urls::http://javax_xml_transform_dom_DOMSource/feature',
        'urls::http://javax_xml_transform_sax_SAXResult/feature',
        'urls::http://javax_xml_transform_sax_SAXSource/feature',
        'urls::http://javax_xml_transform_sax_SAXTransformerFactory/feature',
        'urls::http://javax_xml_transform_sax_SAXTransformerFactory/feature/xmlfilter',
        'urls::http://javax_xml_transform_stream_StreamResult/feature',
        'urls::http://javax_xml_transform_stream_StreamSource/feature',
        'urls::http://relaxng_org/ns/structure/1_0',
        'urls::http://www_w3_org/2001/XMLSchema',
        'urls::http://www_w3_org/2001/XMLSchema-instance',
        'urls::http://www_w3_org/2003/11/xpath-datatypes',
        'urls::http://www_w3_org/TR/REC-xml',
        'urls::http://www_w3_org/xmlns/2000/',
        'urls::http://xml_org/sax/features/namespace-prefixes',
        'urls::http://xml_org/sax/features/namespaces',
        'urls::http://xml_org/sax/features/validation',
        'urls::http://xml_org/sax/properties/declaration-handler',
        'urls::http://xml_org/sax/properties/lexical-handler',
        'urls::http://xmlpull_org/v1/doc/features_html'}

    for k in added_by_soot:
        if k in X_generated and k not in X_original and k not in side_effects:
            del X_generated[k]

    return X_generated


class RetryableFailure(Exception):
    def __init__(self, message):
        super().__init__(message)
