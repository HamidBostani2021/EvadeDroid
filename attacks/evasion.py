
"""
Generating a real-world adversarial example from an Android APK
"""

from attacks import Sample
from timeit import default_timer as timer
import numpy as np
import os
import shutil
import glob
import feature_extraction.drebin as drebin
import transformation.inpatients as inpatients
from transformation import injection
import lib.utils as utils
from settings import config
from attacks import label_virus_total as vt
import random
import pickle
from android_malware_with_n_gram import batch_disasseble, bytecode_extract,n_gram

from mamadroid import mamadroid, MaMaStat

def loss_function(model,x_malware, x_manipulated,malware_detector):
    if malware_detector == "MaMaDroid":
        y_scores_malware = model.clf.predict_proba(x_malware)
        y_scores_adv_malware = model.clf.predict_proba(x_manipulated)
        y_scores_malware = y_scores_malware[0][0]
        y_scores_adv_malware = y_scores_adv_malware[0][0]
        print("y_scores_malware: ", y_scores_malware)
        print("y_scores_adv_malware: ", y_scores_adv_malware)        
        loss = y_scores_adv_malware
        y_pred_adv = model.clf.predict(x_manipulated)[0]
    elif malware_detector == 'AdversarialDeepEnsembleMax':        
        y_scores_adv_malware = model.test_new(x_manipulated,[1],'proba')[0,0]         
        loss = y_scores_adv_malware
        if y_scores_adv_malware >0.5:
            y_pred_adv = 0
        else:
            y_pred_adv = 1        
    else:
        y_scores_malware = model.clf.decision_function(x_malware)
        y_scores_adv_malware = model.clf.decision_function(x_manipulated)    
        loss = -y_scores_adv_malware        
        y_pred_adv = model.clf.predict(x_manipulated)[0] 
    return loss, y_pred_adv

def loss_function_for_hard_label(model,post_op_host, x_manipulated,malware_detector):
    rootdir = config['tmp_dir'] + "smalis"
    res, fullTopath = batch_disasseble.disassemble_adv(post_op_host, rootdir, 3000)   
    if res == 0:
        bytecode_extract.collect_adv(fullTopath,1,post_op_host)     
        loss = n_gram.extract_n_gram_adv(5, post_op_host)         
        print("hard-label-loss: ", loss)        
        print("hard-label-loss after round down: ",loss)
    else:
        loss = 0
    print("post_op_host: ",post_op_host)
    no_detect = 0
    if malware_detector == "Drebin" or malware_detector == "SecSVM" or malware_detector == "MaMaDroid":
        y_pred_adv = model.clf.predict(x_manipulated)[0]
    elif malware_detector == "AdversarialDeepEnsembleMax":
        y_scores_adv_malware = model.test_new(x_manipulated,[1],'proba')[0,0]         
        loss = y_scores_adv_malware
        if y_scores_adv_malware >0.5:
            y_pred_adv = 0
        else:
            y_pred_adv = 1        
    elif malware_detector == "Kaspersky":
        no_detect,Kaspersky, _, _, _, _, _, _, _, _, _ = vt.report(post_op_host)
        y_pred_adv = bool(int(Kaspersky))
    elif malware_detector == "McAfee":
        no_detect,_, _, McAfee, _, _, _, _, _, _, _ = vt.report(post_op_host)
        y_pred_adv = bool(int(McAfee))
    elif malware_detector == "Avira":
        no_detect,_, _, _, _, Avira, _, _, _, _, _= vt.report(post_op_host)
        y_pred_adv = bool(int(Avira))
    elif malware_detector == "Ikarus":
        no_detect,_, _, _, _, _, _, Ikarus, _, _, _ = vt.report(post_op_host)
        y_pred_adv = bool(int(Ikarus))
    elif malware_detector == "BitDefenderFalx":
        no_detect,_, _, _, _, _, _, _, _, BitDefenderFalx, _ = vt.report(post_op_host)
        y_pred_adv = bool(int(BitDefenderFalx))
    elif malware_detector == "Total":
        no_detect,_, _, _, _, _, _, _, _, _, _ = vt.report(post_op_host)
        y_pred_adv = int(no_detect > 0)
    return loss, y_pred_adv,no_detect
    


def generate_adversarial_example(malware, action_set, q, increase_in_size, 
                                 model_inaccessible, hard_label, malware_detector,ignore_optimization):    
   
    query_time = 0
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
    print('Loading host malware...')
    host = inpatients.Host.load(malware)    
    print('Host {host.name} loaded!')
    
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
    elif malware_detector =='AdversarialDeepEnsembleMax':
        x_malware = model_inaccessible.dict_to_feature_vector(malware_dict) 
        y_pred_adv = model_inaccessible.test_new(x_malware,[1],'label')[0]       
        decision_score =  model_inaccessible.test_new(x_malware,[1],'proba')[0,0] 
        new_adv_dict = malware_dict
        L_best = 0 #model_inaccessible.clf.decision_function(x_malware)  
    else:
        new_adv_dict = dict()        
        if malware_detector == "Kaspersky":
            no_detect_best,Kaspersky, _, _, _, _, _, _, _, _, _ = vt.report(malware)
            y_pred_adv = bool(int(Kaspersky))
        elif malware_detector == "McAfee":
            no_detect_best,_, _, McAfee, _, _, _, _, _, _, _ = vt.report(malware)
            y_pred_adv = bool(int(McAfee))
        elif malware_detector == "Avira":
            no_detect_best,_, _, _, _, Avira, _, _, _, _, _= vt.report(malware)
            y_pred_adv = bool(int(Avira))
        elif malware_detector == "Ikarus":
            no_detect_best,_, _, _, _, _, _, Ikarus, _, _, _ = vt.report(malware)
            y_pred_adv = bool(int(Ikarus))
        elif malware_detector == "BitDefenderFalx":
            no_detect_best,_, _, _, _, _, _, _, _, BitDefenderFalx, _ = vt.report(malware)
            y_pred_adv = bool(int(BitDefenderFalx))
        elif malware_detector == "Total":
            no_detect_best,_, _, _, _, _, _, _, _, _, _ = vt.report(malware)
            print('.....................................')
            print("no_detect:",no_detect_best)
            y_pred_adv = int(no_detect_best > 0)
        L_best = 0  
    
    no_detect_per_try=dict()
    if malware_detector == "Total":
        no_detect_per_try[0] = no_detect_best
        
    
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
    
    print("y_pred_adv:",y_pred_adv)
    print("number_of_query:",number_of_query)
    print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    while number_of_query < q and y_pred_adv == 1:      
        print("y_pred_adv:",y_pred_adv)
        print("number_of_query:",number_of_query)
        
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
        if malware_detector == "MaMaDroid" or malware_detector == "Drebin" or malware_detector == "SecSVM" or malware_detector =='AdversarialDeepEnsembleMax':
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
            elif malware_detector == "Drebin" or malware_detector == "SecSVM" or malware_detector =='AdversarialDeepEnsembleMax':
                x_manipulated = model_inaccessible.dict_to_feature_vector(new_adv_dict) 
            else:
                x_manipulated = ""
            
            
            if hard_label == False:
                if malware_detector != "MaMaDroid":
                    L, y_pred_adv = loss_function(model_inaccessible,x_malware,x_manipulated,malware_detector)
                else:
                    L, y_pred_adv = loss_function(model_inaccessible,x_malware_mamadroid,x_manipulated_mamadroid,malware_detector)
            else:
                start_query = timer()
                if malware_detector != "MaMaDroid":
                    L, y_pred_adv,no_detect = loss_function_for_hard_label(model_inaccessible,post_op_host,x_manipulated,malware_detector)
                else:
                    L, y_pred_adv,no_detect = loss_function_for_hard_label(model_inaccessible,post_op_host,x_manipulated_mamadroid,malware_detector)
                end_query = timer()
                query_time += end_query-start_query
           
            if malware_detector != "Drebin" and malware_detector != "SecSVM" and malware_detector != "MaMaDroid" and malware_detector !='AdversarialDeepEnsembleMax':
                if no_detect > no_detect_best:
                    print("no_detect > no_detect_previou: True")
                    L = 0
                else:
                    print("no_detect > no_detect_previou: False")
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
                #USENIX major revision          
                if number_of_query >= 10 and len(M_total) <= 2:
                    L_best = round(L_best,2)
                    L = round(L,2)
                
                loss_cmp = L >= L_best                
                
            print("loss_cmp: "+str(loss_cmp))
            
            #Added for USENIX major revision  
            if ignore_optimization == True:
                loss_cmp = True            
            
            if loss_cmp:
                modified_features_per_query[number_of_query] = no_adv_malware_feature - no_malware_feature
                is_intact = 0
                L_best = L              
                number_of_features_adv_malware_per_query.append(no_adv_malware_feature)
                number_of_api_calls_adv_malware_per_query.append(no_of_api_calls_adv_malware)
                if malware_detector == "Total":
                    no_detect_per_try[len(no_detect_per_try)] = no_detect
            else:
                if malware_detector == "Total":
                    no_detect_per_try[len(no_detect_per_try)] = no_detect_per_try[len(no_detect_per_try)-1]
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
    elif malware_detector =='AdversarialDeepEnsembleMax':
        if is_intact == 0:        
            adv_malware_label = model_inaccessible.test_new(x_manipulated,[1],'label')[0]  
            adv_decision_score = model_inaccessible.test_new(x_manipulated,[1],'proba')[0,0] 
        else:
            adv_malware_label = model_inaccessible.test_new(x_malware,[1],'label')[0]
            adv_decision_score = model_inaccessible.test_new(x_malware,[1],'proba')[0,0]
    else:
        if is_intact == 0:
            if os.path.exists(post_op_host) == False:
                adv_malware_label = 1
            else:                
                start_query = timer()
                if malware_detector == "Kaspersky":
                    _,Kaspersky, _, _, _, _, _, _, _, _, _ = vt.report(post_op_host)
                    adv_malware_label = bool(int(Kaspersky))
                elif malware_detector == "McAfee":
                    _,_, _, McAfee, _, _, _, _, _, _, _ = vt.report(post_op_host)
                    adv_malware_label = bool(int(McAfee))
                elif malware_detector == "Avira":
                    _,_, _, _, _, Avira, _, _, _, _, _= vt.report(post_op_host)
                    adv_malware_label = bool(int(Avira))
                elif malware_detector == "Ikarus":
                    _,_, _, _, _, _, _, Ikarus, _, _, _ = vt.report(post_op_host)
                    adv_malware_label = bool(int(Ikarus))
                elif malware_detector == "BitDefenderFalx":
                    _,_, _, _, _, _, _, _, _, BitDefenderFalx, _ = vt.report(post_op_host)
                    adv_malware_label = bool(int(BitDefenderFalx))
                elif malware_detector == "Total":
                    no_detect,_, _, _, _, _, _, _, _, _, _ = vt.report(post_op_host)
                    adv_malware_label = no_detect == 0
                end_query = timer()
                query_time += end_query-start_query
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
    #execution_time = end - start
    execution_time = end - start - query_time
    print("execution_time: ", execution_time)
    print("query_time: ", query_time)
    classified_with_hard_label = hard_label
    '''
    apk = Sample.APK(app_name,malware_label, adv_malware_label, 
                 number_of_queries, percentage_increasing_size, 
                 number_of_features_malware,number_of_features_adv_malware,
                 number_of_features_adv_malware_per_query,
                 number_of_api_calls_malware,number_of_api_calls_adv_malware,
                 number_of_api_calls_adv_malware_per_query, transformations,
                 intact_due_to_soot_error,execution_time,classified_with_hard_label,query_time)
    '''
    apk = Sample.APK(app_name,malware_label, adv_malware_label, 
             number_of_queries, percentage_increasing_size, 
             number_of_features_malware,number_of_features_adv_malware,
             number_of_features_adv_malware_per_query,
             number_of_api_calls_malware,number_of_api_calls_adv_malware,
             number_of_api_calls_adv_malware_per_query, transformations,
             intact_due_to_soot_error,execution_time,classified_with_hard_label,query_time,
             malware_dict,new_adv_dict)
    
    if malware_detector == "Total":
        return no_detect_per_try
    else:
        return apk

def resign(app_path):
    """Resign the apk."""
    utils.run_java_component(config['resigner'], ['--overwrite', '-a', app_path])