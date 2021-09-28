# -*- coding: utf-8 -*-
"""
This tool is the EvadeDroid's pipeline, a novel problem-space evasion attack for 
black-box based Android malware detection, presented in [1].

[1] "EvadeDroid: A Practical Evasion Attack on Machine Learning for Black-box Android Malware Detection", 
EuroS&P 2022,  Submitted on Sept. 23, 2021. 
"""

from feature_extraction import feature_set
import sys
from transformation import extraction
import lib.utils as utils
import timeit
import black_box_attack.models as models
import json
from attacks import evasion
from attacks import reference_attacks as baseline
import numpy as np
import torch
from itertools import repeat
from settings import config
import pickle
import os
import shutil
mp = torch.multiprocessing.get_context('forkserver')


def main(download_samples,initial_check_apks,accessible_inaccessible_datset_preparation,
         mamadroid_feature_extraction,n_gram_feature_extraction,
         create_action_set,roc_curve,create_Drebin,
         create_SecSVM,evasion_attack_Drebin,evasion_attack_SecSVM,reference_attack_on_Drebin,reference_attack_on_SecSVM,
         mamadroid_malware_feature_extraction,create_MaMaDroid,evasion_attack_MaMaDroid,evasion_attack_vt,vt_engine):       
    
    download_samples = bool(int(download_samples))
    initial_check_apks =bool(int(initial_check_apks))
    accessible_inaccessible_datset_preparation=bool(int(accessible_inaccessible_datset_preparation))  
    mamadroid_feature_extraction = bool(int(mamadroid_feature_extraction))
    n_gram_feature_extraction = bool(int(n_gram_feature_extraction))
    create_action_set = bool(int(create_action_set))
    roc_curve = bool(int(roc_curve))
    create_Drebin = bool(int(create_Drebin))
    create_SecSVM = bool(int(create_SecSVM))
    
    evasion_attack_Drebin = bool(int(evasion_attack_Drebin))
    evasion_attack_SecSVM = bool(int(evasion_attack_SecSVM))
    reference_attack_on_Drebin = bool(int(reference_attack_on_Drebin))
    reference_attack_on_SecSVM = bool(int(reference_attack_on_SecSVM))
    mamadroid_malware_feature_extraction = bool(int(mamadroid_malware_feature_extraction))
    create_MaMaDroid = bool(int(create_MaMaDroid))
    evasion_attack_MaMaDroid = bool(int(evasion_attack_MaMaDroid))
    
    evasion_attack_vt = bool(int(evasion_attack_vt))    
    if vt_engine =="ESETNOD32":
        vt_engine = "ESET-NOD32"   
    
    
    if download_samples == True:
        print("~~~~~~~~~~~~~~~~~~~ Start - downloading samples ~~~~~~~~~~~~~~~~~~~")
        feature_set.create_sub_dataset()
        feature_set.create_csv_from_meta_sub_dataset()       
    
        '''
        Now, download apks determined in the obtained metafile from AndroZoo 
        and put them in the following path:
        
        <C:/AndroidDatasets/AndooZoo> 
        
        Note in using az command, you may come across an exception related dex_date field. 
        I this case, first of all, open csv file with notepad and then replace 
        the values of this field with a proper value like 2021-07-09 00:00:00.
        
        Then copy apks in ../data/apks/sub_dataset/
        '''
        print("~~~~~~~~~~~~~~~~~~~ Complete - downloading samples ~~~~~~~~~~~~~~~~~~~")
    
    if initial_check_apks == True:
        print("~~~~~~~~~~~~~~~~~~~ Start - selecting EvadeDroid's malware samples after checking the validity of accessible malware  samples ~~~~~~~~~~~~~~~~~~~")
        feature_set.check_malware_apks()
        print("~~~~~~~~~~~~~~~~~~~ Complete - selecting EvadeDroid's malware samples after checking the validity of accessible malware  samples ~~~~~~~~~~~~~~~~~~~")
    
    if accessible_inaccessible_datset_preparation == True:
        print("~~~~~~~~~~~~~~~~~~~ Start - determining accessible and inaccessible datasets preparation ~~~~~~~~~~~~~~~~~~~")
        feature_set.determine_smaples_accessible_inaccessible()
        print("~~~~~~~~~~~~~~~~~~~ Complete - determining accessible and inaccessible datasets preparation ~~~~~~~~~~~~~~~~~~~")
    
    if mamadroid_feature_extraction == True:
        print("~~~~~~~~~~~~~~~~~~~ Start - feature extraction for MaMaDroid ~~~~~~~~~~~~~~~~~~~")
        feature_set.extract_mamadriod_features()
        print("~~~~~~~~~~~~~~~~~~~ Complete - feature extraction for MaMaDroid ~~~~~~~~~~~~~~~~~~~")
    if n_gram_feature_extraction == True:
        print("~~~~~~~~~~~~~~~~~~~ Start - n-gram-based feature extraction ~~~~~~~~~~~~~~~~~~~")
        feature_set.extract_n_gram_features()
        print("~~~~~~~~~~~~~~~~~~~ Complete - n-gram-based feature extraction ~~~~~~~~~~~~~~~~~~~")
        
    if create_action_set == True:
        start = timeit.timeit()          
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start - preparing action set ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start - preparing action set ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        donors_path = os.path.join(config['stored_components'],'donors.p')
        if os.path.exists(donors_path) == True:
            with open(donors_path,'rb') as f:
                malware_donors = pickle.load(f)
        else:
            print("donors.p was not found")
            utils.perform_logging("donors.p was not found")
            return
        donors = [val for id,val in enumerate(malware_donors.values())]
        donors = list(dict.fromkeys(donors))
        extraction.create_action_set(donors)
        end = timeit.timeit()
        print("elapsed time:" + str(end - start))
        utils.perform_logging("elapsed time:" + str(end - start))    
        print("~~~~~~~~~~~~~~~~~~~~~~~~~ Complete - preparing action set ~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~ Complete - preparing action set ~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("Next component ...")
  
    if roc_curve == True:
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start - ROC analysis ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start - ROC analysis  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")       
        models.create_roc_curve()                
        print("~~~~~~~~~~~~~~~~~~~~~~~~~ Complete - ROC analysis  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~ Complete - ROC analysis  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("Next component ...")
    
    X = list()
    malware_app_indices = list()
    if create_Drebin == True or create_SecSVM == True or create_MaMaDroid == True: 
        path = os.path.join(config['features'] , 'sub_dataset/', 'accessible_malware_index.p')
        with open(path,'rb') as f:
            malware_app = pickle.load(f) 
        
        X_filename = os.path.join(config['features'] , 'sub_dataset/', 'sub_dataset-X.json')   
        with open(X_filename, 'rt') as f:
            X = json.load(f)        
        malware_app_indices = [item for item in malware_app.values()]
        malware_app = [item for item in malware_app.keys()]

    if create_Drebin == True:   
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start preparing DREBIN ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start preparing DREBIN  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        model_inaccessible_Drebin = models.SVM("Drebin", False, config['X_dataset_inaccessible'], config['Y_dataset_inaccessible'],
                                  config['meta_inaccessible'],num_features = None,append = None)
        
        if os.path.exists(model_inaccessible_Drebin.model_name):
            model_inaccessible_Drebin = models.load_from_file(model_inaccessible_Drebin.model_name)
        else:
            print("Generate Drebin model ...")
            model_inaccessible_Drebin.generate()           
        
        y_pred = list()
        for app_index in malware_app_indices:
            malware_dict = X[app_index]
            x_malware = model_inaccessible_Drebin.dict_to_feature_vector(malware_dict) 
            y_pred_app = model_inaccessible_Drebin.clf.predict(x_malware)   
            y_pred.append(y_pred_app)
        DR = (sum(y_pred)/len(malware_app_indices))*100            
        print("DR (DREBIN):" + str(DR) + "%")
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End preparing DREBIN ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End preparing DREBIN  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    

    if create_SecSVM == True: 
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start preparing SecSVM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start preparing SecSVM  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        model_inaccessible_SecSVM = models.SecSVM("SecSVM",False, config['X_dataset_inaccessible'], config['Y_dataset_inaccessible'],
                                  config['meta_inaccessible'], num_features=None,
                                  secsvm_k=0.2, secsvm=False, secsvm_lr=0.0001,
                                  secsvm_batchsize=1024, secsvm_nepochs=20, seed_model=None)
        
        if os.path.exists(model_inaccessible_SecSVM.model_name):
            model_inaccessible_SecSVM = models.load_from_file(model_inaccessible_SecSVM.model_name)
        else:
            model_inaccessible_SecSVM.generate()       
        
        y_pred = list()
        for app_index in malware_app_indices:
            malware_dict = X[app_index]
            x_malware = model_inaccessible_SecSVM.dict_to_feature_vector(malware_dict) 
            y_pred_app = model_inaccessible_SecSVM.clf.predict(x_malware)   
            y_pred.append(y_pred_app[0])
        DR = (sum(y_pred)/len(malware_app_indices))*100
        print("DR (SecSVM):" + str(DR) + "%")
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End preparing SecSVM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End preparing SecSVM  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        
    if create_MaMaDroid == True:
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start preparing MaMaDroid ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start preparing MaMaDroid  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        model_inaccessible = models.SVM("Drebin", False, config['X_dataset_inaccessible'], config['Y_dataset_inaccessible'],
                                      config['meta_inaccessible'])
        model_inaccessible = models.load_from_file(model_inaccessible.model_name)
        path = os.path.join(config['mamadroid'],'Features/Families/dataset_inaccessible.p')    
        model_mamadroid = models.SVM("MaMaDroid", False, path, model_inaccessible.y_train,
                             model_inaccessible.m_train)  
                 
        if os.path.exists(model_mamadroid.model_name):
             model_mamadroid = models.load_from_file(model_mamadroid.model_name)
        else:
             model_mamadroid.generate_mamadroid(no_training_sample=11050)       
       
        
        path = os.path.join(config['mamadroid'],'Features/Families/dataset_accessible_malware.p')
        with open(path,'rb') as f:
            malware_list_mama_features =  pickle.load(f)
        malware_list_mama_features.pop(0)
        malware_app = [os.path.splitext(item[0])[0] + '.apk' for item in malware_list_mama_features]
        malware_list = np.array([np.array(item[1:]) for idx,item in enumerate(malware_list_mama_features)])
        y_pred = model_mamadroid.clf.predict(malware_list)
        DR = (sum(y_pred)/len(malware_list))*100
        print("DR (MaMaDroid): " + str(DR) + "%")
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End preparing MaMaDroid ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End preparing MaMaDroid  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    if evasion_attack_Drebin == True:         
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: evasion attack on DREBIN ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: evasion attack on DREBIN  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        action_set_path = os.path.join(config['stored_components'],'action_set.p')        
        with open(action_set_path, 'rb') as f:
            action_set = pickle.load(f) 
        for item in action_set.keys():
            organ_path = action_set[item] 
            with open(organ_path, 'rb') as f:
                organ = pickle.load(f) 
            action_set[item]  = organ        
        number_of_query = 20
        base_size = 0.1
        malware_detector = "Drebin"
        hard_label = False
        
        path_base = os.path.join(config['results_dir'],'EvadeDroid/Drebin')
        if os.path.isdir(path_base) == False:
            os.mkdir(path_base)
       
        malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]
        malware_apps_path = [os.path.join(config['apks_accessible'],'malware',item) for idx_item,item in enumerate(malware_app) if idx_item in malware_idx]
        
        for s in range(1,6):               
            if hard_label == True:
               hardlabel = 1
            else:
               hardlabel = 0            
            increase_in_size = base_size * s
            name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
            path = os.path.join(path_base,name)
            if os.path.isdir(path) == False:
                os.mkdir(path)
                
            
            increase_in_size_temp = base_size * (s - 1)
            name_temp = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size_temp,hardlabel)
            path_temp = os.path.join(path_base,name_temp)
            if os.path.isdir(path_temp) == True:                    
                apk_name = os.listdir(path_temp)                    
                for app in apk_name:        
                    apk_info_path = os.path.join(path_temp,app)
                    with open(apk_info_path , 'rb') as f:
                        apk = pickle.load(f)                        
                    
                    if apk.adv_malware_label == 0:                            
                        if apk.number_of_queries <= 2:
                            source = os.path.join(path_temp,app)
                            destination = os.path.join(path,app)
                            shutil.copy(source, destination)
            
            print("increase_in_size: ",increase_in_size)
            
            serial = False
            if serial == True:
                for app_path in malware_apps_path:
                    do_black_box_attack(app_path,action_set,number_of_query,increase_in_size,
                        model_inaccessible_Drebin,hard_label,malware_detector,path)
            else:
                with mp.Pool(processes=config['nprocs_evasion']) as p:
                        p.starmap(do_black_box_attack, zip(malware_apps_path,                                            
                                                            repeat(action_set),
                                                            repeat(number_of_query),
                                                            repeat(increase_in_size),
                                                            repeat(model_inaccessible_Drebin),
                                                            repeat(hard_label),
                                                            repeat(malware_detector),
                                                            repeat(path)))
 
            print("Finish attacking  ...")               
            if s != 5:
                shutil.rmtree(os.path.join(config['results_dir'],'hosts'))
                shutil.rmtree(os.path.join(config['results_dir'],'postop'))
                os.mkdir(os.path.join(config['results_dir'],'hosts'))
                os.mkdir(os.path.join(config['results_dir'],'postop'))
            else:
                path_temp = os.path.join(config['results_dir'],'hosts')
                if len(os.listdir(path_temp)) > 0:
                    os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-Drebin-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
                    os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-Drebin-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
                    os.mkdir(os.path.join(config['results_dir'],'hosts'))
                    os.mkdir(os.path.join(config['results_dir'],'postop'))        
        
        hard_label = True
        base_size = 0.1
        s = 5
        if hard_label == True:
           hardlabel = 1
        else:
           hardlabel = 0            
        increase_in_size = base_size * s
        name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
        path = os.path.join(path_base,name)
        if os.path.isdir(path) == False:
            os.mkdir(path)
        
        print("increase_in_size: ",increase_in_size)
        
        serial = False
        if serial == True:
            for app_path in malware_apps_path:
                do_black_box_attack(app_path,action_set,number_of_query,increase_in_size,
                    model_inaccessible_Drebin,hard_label,malware_detector,path)
        else:
            with mp.Pool(processes=config['nprocs_evasion']) as p:
                    p.starmap(do_black_box_attack, zip(malware_apps_path,                                            
                                                        repeat(action_set),
                                                        repeat(number_of_query),
                                                        repeat(increase_in_size),
                                                        repeat(model_inaccessible_Drebin),
                                                        repeat(hard_label),
                                                        repeat(malware_detector),
                                                        repeat(path)))
 
        print("Finish attacking  ...")                 
        if s != 5:
            shutil.rmtree(os.path.join(config['results_dir'],'hosts'))
            shutil.rmtree(os.path.join(config['results_dir'],'postop'))
            os.mkdir(os.path.join(config['results_dir'],'hosts'))
            os.mkdir(os.path.join(config['results_dir'],'postop'))
        else:
            os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-Drebin-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
            os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-Drebin-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
            os.mkdir(os.path.join(config['results_dir'],'hosts'))
            os.mkdir(os.path.join(config['results_dir'],'postop'))
        
        
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on DREBIN ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on DREBIN ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")


    if evasion_attack_SecSVM == True:         
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: evasion attack on SecSVM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: evasion attack on SecSVM  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        action_set_path = os.path.join(config['stored_components'],'action_set.p')        
        with open(action_set_path, 'rb') as f:
            action_set = pickle.load(f) 
        for item in action_set.keys():
            organ_path = action_set[item] 
            with open(organ_path, 'rb') as f:
                organ = pickle.load(f) 
            action_set[item]  = organ        
        number_of_query = 20
        base_size = 0.1
        malware_detector = "SecSVM"
        hard_label = False
        
        path_base = os.path.join(config['results_dir'],'EvadeDroid/SecSVM')
        if os.path.isdir(path_base) == False:
            os.mkdir(path_base)
       
        malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]
        malware_apps_path = [os.path.join(config['apks_accessible'],'malware',item) for idx_item,item in enumerate(malware_app) if idx_item in malware_idx]
     
        
        hard_label = False
        base_size = 0.1
        s = 5
        if hard_label == True:
           hardlabel = 1
        else:
           hardlabel = 0            
        increase_in_size = base_size * s
        name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
        path = os.path.join(path_base,name)
        if os.path.isdir(path) == False:
            os.mkdir(path)
        
        print("increase_in_size: ",increase_in_size)
        
        serial = False
        if serial == True:
            for app_path in malware_apps_path:
                do_black_box_attack(app_path,action_set,number_of_query,increase_in_size,
                    model_inaccessible_SecSVM,hard_label,malware_detector,path)
        else:
            with mp.Pool(processes=config['nprocs_evasion']) as p:
                    p.starmap(do_black_box_attack, zip(malware_apps_path,                                            
                                                        repeat(action_set),
                                                        repeat(number_of_query),
                                                        repeat(increase_in_size),
                                                        repeat(model_inaccessible_SecSVM),
                                                        repeat(hard_label),
                                                        repeat(malware_detector),
                                                        repeat(path)))
 
        print("Finish attacking  ...")                 
        if s != 5:
            shutil.rmtree(os.path.join(config['results_dir'],'hosts'))
            shutil.rmtree(os.path.join(config['results_dir'],'postop'))
            os.mkdir(os.path.join(config['results_dir'],'hosts'))
            os.mkdir(os.path.join(config['results_dir'],'postop'))
        else:
            os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-Drebin-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
            os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-Drebin-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
            os.mkdir(os.path.join(config['results_dir'],'hosts'))
            os.mkdir(os.path.join(config['results_dir'],'postop'))
        
        
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on SecSVM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on SecSVM ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    
    
    if evasion_attack_MaMaDroid == True: 
        
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: evasion attack on MaMaDroid ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: evasion attack on MaMaDroid  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        action_set_path = os.path.join(config['stored_components'],'action_set.p')        
        with open(action_set_path, 'rb') as f:
            action_set = pickle.load(f) 
        for item in action_set.keys():
            organ_path = action_set[item] 
            with open(organ_path, 'rb') as f:
                organ = pickle.load(f) 
            action_set[item]  = organ       
        number_of_query = 20
        base_size = 0.1
        malware_detector = "MaMaDroid"
        hard_label = False
        
        path_base = os.path.join(config['results_dir'],'EvadeDroid/MaMaDroid')
        if os.path.isdir(path_base) == False:
            os.mkdir(path_base)
       
        malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]    
        malware_apps_path = [os.path.join(config['apks_accessible'],'malware',item) for idx_item,item in enumerate(malware_app) if idx_item in malware_idx]
        print("len(malware_apps_path): " ,len(malware_apps_path))
        
        hard_label = False
        base_size = 0.1
        s = 5
        if hard_label == True:
           hardlabel = 1
        else:
           hardlabel = 0            
        increase_in_size = base_size * s
        name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
        path = os.path.join(path_base,name)
        if os.path.isdir(path) == False:
            os.mkdir(path)
        
        print("increase_in_size: ",increase_in_size)
        
        serial = False
        if serial == True:
            for app_path in malware_apps_path:
                do_black_box_attack(app_path,action_set,number_of_query,increase_in_size,
                    model_mamadroid,hard_label,malware_detector,path)
        else:
            with mp.Pool(processes=config['nprocs_evasion']) as p:
                    p.starmap(do_black_box_attack, zip(malware_apps_path,                                            
                                                        repeat(action_set),
                                                        repeat(number_of_query),
                                                        repeat(increase_in_size),
                                                        repeat(model_mamadroid),
                                                        repeat(hard_label),
                                                        repeat(malware_detector),
                                                        repeat(path)))
 
                         
        print("Finish attacking  ...")
        if s != 5:
            shutil.rmtree(os.path.join(config['results_dir'],'hosts'))
            shutil.rmtree(os.path.join(config['results_dir'],'postop'))
            os.mkdir(os.path.join(config['results_dir'],'hosts'))
            os.mkdir(os.path.join(config['results_dir'],'postop'))
        else:
            os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-MaMaDroid-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
            os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-MaMaDroid-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
            os.mkdir(os.path.join(config['results_dir'],'hosts'))
            os.mkdir(os.path.join(config['results_dir'],'postop'))
        
        
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on MaMaDroid ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on MaMaDroid ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    
    if reference_attack_on_Drebin == True or reference_attack_on_SecSVM == True: 
        model_name = ""
        if reference_attack_on_Drebin == True:
            model = model_inaccessible_Drebin
            model_name = "Drebin"
        else:
            model = model_inaccessible_SecSVM
            model_name = "SecSVM"
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: reference attack on %s ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" %(model_name))
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: reference attack on %s  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"%(model_name))
        
        detected_malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]
        #malware_apps_name = [item for idx_item,item in enumerate(malware_app) if idx_item in detected_malware_idx]  
        path_fail = os.path.join(config['stored_components'],'malware_apk_fail.p')    
        with open(path_fail, 'rb') as f:
            malware_apk_fail = pickle.load(f)        
        
        no_modifiable_features_random_attack = 200
        y_pred_random_attack = list()
        for i in detected_malware_idx:
            if malware_app[i] in malware_apk_fail:
                continue
            x_dict = X[malware_app_indices[i]]
            x = model.dict_to_feature_vector(x_dict) 
            x = x.toarray()
            _,x_adv_dict = baseline.random_attack(x,len(model.vec.feature_names_),no_modifiable_features_random_attack,model.vec.feature_names_)
            x_adv = model.dict_to_feature_vector(x_adv_dict) 
            y_adv = model.clf.predict(x_adv)   
            y_pred_random_attack.append(y_adv[0])
            
        no_evasion = [val for val in y_pred_random_attack if val == 0]
        ER_random_attack = (len(no_evasion)/len(y_pred_random_attack))*100  
        print("ER_random_attack: ",ER_random_attack)        
        
        no_modifiable_features_pk_attack = 8
        y_pred_pk_attack = list()
        for i in detected_malware_idx:
            
            if malware_app[i] in malware_apk_fail:
                continue
            
            x_dict = X[malware_app_indices[i]]
            x = model.dict_to_feature_vector(x_dict) 
            x = x.toarray()
            _,x_adv_dict = baseline.pk_attack(x,no_modifiable_features_pk_attack,model.clf.coef_,model.vec.feature_names_)
            x_adv = model.dict_to_feature_vector(x_adv_dict) 
            y_adv = model.clf.predict(x_adv)   
            y_pred_pk_attack.append(y_adv[0])
            
        no_evasion = [val for val in y_pred_pk_attack if val == 0]
        ER_random_attack = (len(no_evasion)/len(y_pred_pk_attack))*100  
        print("ER_pk_attack: ",ER_random_attack)       
       
        
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: reference attack on %s ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" %(model_name))
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: reference attack on %s  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"%(model_name))
    
  
    if mamadroid_malware_feature_extraction == True:
        print("~~~~~~~~~~~~~~~~~~~ Start malware feature extraction for MaMaDroid ~~~~~~~~~~~~~~~~~~~")
        feature_set.extract_mamadriod_malware_features()
        print("~~~~~~~~~~~~~~~~~~~ Finish malware feature extraction for MaMaDroid ~~~~~~~~~~~~~~~~~~~")


    if evasion_attack_vt == True:         
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: evasion attack on VirusTotal ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: evasion attack on VirusTotal  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        action_set_path = os.path.join(config['stored_components'],'action_set.p')        
        with open(action_set_path, 'rb') as f:
            action_set = pickle.load(f) 
        for item in action_set.keys():
            organ_path = action_set[item] 
            with open(organ_path, 'rb') as f:
                organ = pickle.load(f) 
            action_set[item]  = organ        
        number_of_query = 10 
        base_size = 0.1
        malware_detector = vt_engine
        hard_label = False
        
        path_base = os.path.join(config['results_dir'],'EvadeDroid/VirusTotal')
        if os.path.isdir(path_base) == False:
            os.mkdir(path_base)
            
        if malware_detector == "ESET-NOD32":
            base_path = os.path.join(config['apks_accessible'],'vt_engines',"ESETNOD32")
        else:
            base_path = os.path.join(config['apks_accessible'],'vt_engines',malware_detector)
        malware_apps = os.listdir(base_path)     
       
        malware_apps_path = [os.path.join(base_path,item) for item in malware_apps]         
        
        hard_label = True
        base_size = 0.1
        s = 5
        if hard_label == True:
           hardlabel = 1
        else:
           hardlabel = 0            
        increase_in_size = base_size * s
        print("malware_detector: ",malware_detector)
        if malware_detector == "ESET-NOD32":
            name = "result_%s"%("ESETNOD32")
        else:
            name = "result_%s"%(malware_detector)
        path = os.path.join(path_base,name)
        if os.path.isdir(path) == False:
            os.mkdir(path)
        
        print("increase_in_size: ",increase_in_size)
        empty_model = []
        for app_path in malware_apps_path:
                do_black_box_attack(app_path,action_set,number_of_query,increase_in_size,
                    empty_model,hard_label,malware_detector,path)
        print("Finish attacking  ...")                 
        '''
        os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts_%s'%(malware_detector)))
        os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop_%s'%(malware_detector)))
        os.mkdir(os.path.join(config['results_dir'],'hosts'))
        os.mkdir(os.path.join(config['results_dir'],'postop'))
        '''
        
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on VirusTotal ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on VirusTotal ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")


def do_black_box_attack(app_path,action_set,number_of_query,increase_in_size,
                        model_inaccessible,hard_label,malware_detector,path):    
        
    path_fail = os.path.join(config['stored_components'],'malware_apk_fail.p')    
    with open(path_fail, 'rb') as f:
        malware_apk_fail = pickle.load(f)
    if os.path.basename(app_path) in malware_apk_fail:
        print("app is corrupt")
        return
    
    #path_base = os.path.join(config['results_dir'],'EvadeDroid/Drebin','result-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,(hard_label * 1)))
    if malware_detector == "Drebin" or malware_detector == "SecSVM" or malware_detector == "MaMaDroid":
        path_base = os.path.join(config['results_dir'],'EvadeDroid/%s'%(malware_detector),'result-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,(hard_label * 1)))
    else:
        if malware_detector == "ESET-NOD32":
           name = "result_%s"%("ESETNOD32") 
        else:
            name = "result_%s"%(malware_detector)
        path_base = os.path.join(config['results_dir'],'EvadeDroid/VirusTotal/%s'%(name))
    #path_base_temp = path_base +'/back'
    apps_checked = os.listdir(path_base)
    
    
    if os.path.splitext(os.path.basename(app_path))[0] +'.p' in apps_checked:
        print('%s has been already checked'%(os.path.basename(app_path)))
        return
     
    '''
    app_temp = os.path.splitext(os.path.basename(app_path))[0] +'.p'
    apk_info_path = os.path.join(path_base,app_temp)
    with open(apk_info_path , 'rb') as f:
        apk = pickle.load(f)
    if apk.adv_malware_label == 0:
        print("app has been already manipulated successfully")
        return
    
   '''
    
    
    print("----------------------------------------------------")
    no_finished_apps = len(os.listdir(path))
    print("no_finished_apps = " + str(no_finished_apps))
    
    malware = app_path#os.path.join(config['apks_accessible'],'malware',malware_app[i])
    
    apk = evasion.generate_adversarial_example(malware, action_set, number_of_query, 
                                         increase_in_size, model_inaccessible, 
                                         hard_label, malware_detector)
    print("app_name = ", apk.app_name)
    print("malware_label = ",apk.malware_label)
    print("adv_malware_label = ",apk.adv_malware_label)
    print("number_of_queries = ",apk.number_of_queries)
    print("percentage_increasing_size = ",apk.percentage_increasing_size)
    print("number_of_features_malware = ",apk.number_of_features_malware)
    print("number_of_features_adv_malware = ",apk.number_of_features_adv_malware)
    print("number_of_features_adv_malware_per_query = ",apk.number_of_features_adv_malware_per_query)
    print("number_of_api_calls_malware = ",apk.number_of_api_calls_malware)
    print("number_of_api_calls_adv_malware = ",apk.number_of_api_calls_adv_malware)
    print("number_of_api_calls_adv_malware_per_query = ",apk.number_of_api_calls_adv_malware_per_query)
    print("transformations = ",apk.transformations)
    print("intact_due_to_soot_error = ",apk.intact_due_to_soot_error)
    print("execution_time =  ",apk.execution_time)
    print("classified_with_hard_label = ",apk.classified_with_hard_label)
   
    
    
    #apk_info_path = os.path.join(path,apk.app_name.replace('.apk','.p'))
    apk_info_path = os.path.join(path,os.path.splitext(apk.app_name)[0] +'.p')
    with open(apk_info_path , 'wb') as f:
        pickle.dump(apk,f)
        print("copy done: %s"%(apk_info_path))
    print("----------------------------------------------------")   

if __name__ == "__main__":
    download_samples = False
    initial_check_apks =False
    accessible_inaccessible_datset_preparation=False  
    mamadroid_feature_extraction = False
    n_gram_feature_extraction = False
    create_action_set = False
    roc_curve = False
    create_Drebin = False
    create_SecSVM = True
    evasion_attack_Drebin = False
    evasion_attack_SecSVM = False
    reference_attack_on_Drebin = False
    reference_attack_on_SecSVM = False
    mamadroid_malware_feature_extraction = False
    create_MaMaDroid = False
    evasion_attack_MaMaDroid = False
    evasion_attack_vt = True
    vt_engine = "Kaspersky"
    
    main(sys.argv[1], sys.argv[2],sys.argv[3],sys.argv[4],sys.argv[5],sys.argv[6],
    sys.argv[7],sys.argv[8],sys.argv[9],sys.argv[10],sys.argv[11],sys.argv[12],
    sys.argv[13],sys.argv[14],sys.argv[15],sys.argv[16],sys.argv[17],sys.argv[18])
    