# -*- coding: utf-8 -*-
"""
This tool is the EvadeDroid's pipeline, a problem-space evasion attack for 
black-box based Android malware detection.

"""

import argparse
import lib.utils as utils
import timeit
import json
import numpy as np
from itertools import repeat
from settings import config
import pickle
import os
import shutil
from scipy.sparse import csr_matrix
from sklearn.metrics import confusion_matrix
import feature_extraction.drebin as drebin
from attacks import evasion
from attacks import reference_attacks as baseline
import attacks.models as models
from program_slicing.transformation import extraction
from feature_extraction import feature_set
from ade_ma.defender import AdversarialDeepEnsembleMax   


model_AdversarialDeepEnsembleMax = AdversarialDeepEnsembleMax() 
model_AdversarialDeepEnsembleMax.malware_detector = "AdversarialDeepEnsembleMax" 

import torch
mp = torch.multiprocessing.get_context('forkserver')


def main(args):
    
    download_samples = args.download_samples #1
    initial_check_apks =args.initial_check_apks#2
    accessible_inaccessible_datset_preparation=args.accessible_inaccessible_datset_preparation#3
    mamadroid_feature_extraction = args.mamadroid_feature_extraction#4
    n_gram_feature_extraction = args.n_gram_feature_extraction#5
    create_action_set = args.create_action_set#6
    roc_curve = args.roc_curve#7
    create_Drebin = args.create_Drebin#8
    create_SecSVM = args.create_SecSVM#9
    evasion_attack_Drebin = args.evasion_attack_Drebin#10
    evasion_attack_SecSVM = args.evasion_attack_SecSVM#11
    reference_attack_on_Drebin = args.reference_attack_on_Drebin#12
    reference_attack_on_SecSVM = args.reference_attack_on_SecSVM#13
    mamadroid_malware_feature_extraction = args.mamadroid_malware_feature_extraction#14
    create_MaMaDroid = args.create_MaMaDroid#15
    evasion_attack_MaMaDroid = args.evasion_attack_MaMaDroid#16
    evasion_attack_vt = args.evasion_attack_vt#17
    vt_engine = args.vt_engine#'Kaspersky', 'McAfee', 'Avira', 'Ikarus', 'BitDefenderFalx'#18   
    create_AdversarialDeepEnsembleMax = args.create_AdversarialDeepEnsembleMax#19
    evasion_attack_AdversarialDeepEnsembleMax = args.evasion_attack_AdversarialDeepEnsembleMax#20
    check_transferability = args.check_transferability#21    
    substitute = args.substitute#'Drebin' #22 #'AdversarialDeepEnsembleMax', 'SecSVM','MaMaDroid'    
    traget_model_name = args.traget_model_name#'MaMaDroid'#23 #'AdversarialDeepEnsembleMax','Drebin','SecSVM','AdversarialDeepEnsembleMax'
    ignore_optimization = args.ignore_optimization#False #24
    reference_attack_on_AdversarialDeepEnsembleMax = args.reference_attack_on_AdversarialDeepEnsembleMax#False #25
    adversarial_retraining = args.adversarial_retraining#True #26
    malware_name = args.malware_name#True #27  

    
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
    if create_Drebin == True or create_SecSVM == True or create_MaMaDroid == True or create_AdversarialDeepEnsembleMax == True: 
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
            print("model_inaccessible_Drebin.model_name:",model_inaccessible_Drebin.model_name)
            print("Generate Drebin model ...")
            model_inaccessible_Drebin.generate()           
        
        y_pred = list()
        for app_index in malware_app_indices:
            malware_dict = X[app_index]
            x_malware = model_inaccessible_Drebin.dict_to_feature_vector(malware_dict) 
            y_pred_app = model_inaccessible_Drebin.clf.predict(x_malware)   
            y_pred.append(y_pred_app)
        ACC = (sum(y_pred)/len(malware_app_indices))*100            
        print("ACC (DREBIN):" + str(ACC[0]) + "%")
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
        ACC = (sum(y_pred)/len(malware_app_indices))*100
        print("ACC (SecSVM):" + str(ACC) + "%")
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
    
    if create_AdversarialDeepEnsembleMax == True:   
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: Prepare AdversarialDeepEnsembleMax ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: Prepare AdversarialDeepEnsembleMax  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        y_pred = list()
        i = 1
        import config as cfg
        feature_vectors_of_attacker = list()
        
        for app_index in malware_app_indices:
            malware_dict = X[app_index]
            x_malware = model_AdversarialDeepEnsembleMax.dict_to_feature_vector(malware_dict) 
            y_pred_app = model_AdversarialDeepEnsembleMax.test_new(x_malware,[1],'label') 
            if y_pred_app[0] == 1:
                if len(feature_vectors_of_attacker) == 0:
                    feature_vectors_of_attacker = x_malware
                else:
                    feature_vectors_of_attacker = np.append(feature_vectors_of_attacker,x_malware,axis = 0)
                
            y_pred.append(y_pred_app[0])
            '''
            if len(y_pred) == 10:
                break
            '''
            print("i= ",i)
            i +=1
        ACC = (sum(y_pred)/len(malware_app_indices))*100            
        print("ACC (AdversarialDeepEnsembleMax):" + str(ACC) + "%")
        from tools import utils as utils_dnn
        import config as cfg
        utils_dnn.dumpdata_np(feature_vectors_of_attacker, cfg.config.get('attack', 'attackX'))
        
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: Prepare AdversarialDeepEnsembleMax ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: Prepare AdversarialDeepEnsembleMax  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    
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
        hard_label = True
        
        
        if ignore_optimization == False:
            path_base = os.path.join(config['results_dir'],'EvadeDroid/Drebin')
        else:
            path_base = os.path.join(config['results_dir'],'EvadeDroid_ignore_optimization')
        if os.path.isdir(path_base) == False:
            os.mkdir(path_base)
       
        malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]
        malware_apps_path = [os.path.join(config['apks_accessible'],'malware',item) for idx_item,item in enumerate(malware_app) if idx_item in malware_idx]
        if hard_label == False:        
            for s in range(1,6):  
                if ignore_optimization == True:
                  s = 5
                if hard_label == True:
                   hardlabel = 1
                else:
                   hardlabel = 0            
                increase_in_size = base_size * s
                if ignore_optimization == False:
                    name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
                else:
                    name = "Drebin"
                path = os.path.join(path_base,name)
                if os.path.isdir(path) == False:
                    os.mkdir(path)
                    
                
                if ignore_optimization == False:
                    increase_in_size_temp = base_size * (s - 1)
                    name_temp = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size_temp,hardlabel)
                else:
                    name_temp = "Drebin"
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
                            model_inaccessible_Drebin,hard_label,malware_detector,path,ignore_optimization)
                else:
                    with mp.Pool(processes=config['nprocs_evasion']) as p:
                            p.starmap(do_black_box_attack, zip(malware_apps_path,                                            
                                                                repeat(action_set),
                                                                repeat(number_of_query),
                                                                repeat(increase_in_size),
                                                                repeat(model_inaccessible_Drebin),
                                                                repeat(hard_label),
                                                                repeat(malware_detector),
                                                                repeat(path),
                                                                repeat(ignore_optimization)))
     
                print("Finish attacking  ...")               
                if s != 5:
                    shutil.rmtree(os.path.join(config['results_dir'],'hosts'))
                    shutil.rmtree(os.path.join(config['results_dir'],'postop'))
                    os.mkdir(os.path.join(config['results_dir'],'hosts'))
                    os.mkdir(os.path.join(config['results_dir'],'postop'))
                else:
                    path_temp = os.path.join(config['results_dir'],'hosts')
                    if len(os.listdir(path_temp)) > 0:
                        if ignore_optimization == False:
                            os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-Drebin-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
                            os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-Drebin-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
                        else:
                            os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-Drebin-ignore_optimization'))
                            os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-Drebin-ignore_optimization'))
                        os.mkdir(os.path.join(config['results_dir'],'hosts'))
                        os.mkdir(os.path.join(config['results_dir'],'postop'))  
                if ignore_optimization == True:
                    break
              
        
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
                    model_inaccessible_Drebin,hard_label,malware_detector,path,ignore_optimization)
        else:
            with mp.Pool(processes=config['nprocs_evasion']) as p:
                    p.starmap(do_black_box_attack, zip(malware_apps_path,                                            
                                                        repeat(action_set),
                                                        repeat(number_of_query),
                                                        repeat(increase_in_size),
                                                        repeat(model_inaccessible_Drebin),
                                                        repeat(hard_label),
                                                        repeat(malware_detector),
                                                        repeat(path),
                                                        repeat(ignore_optimization)))
 
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
        hard_label = True#False
        
        if ignore_optimization == False:
            path_base = os.path.join(config['results_dir'],'EvadeDroid/SecSVM')
        else:
            path_base = os.path.join(config['results_dir'],'EvadeDroid_ignore_optimization')
        
       
        if os.path.isdir(path_base) == False:
            os.mkdir(path_base)
       
        malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]
        malware_apps_path = [os.path.join(config['apks_accessible'],'malware',item) for idx_item,item in enumerate(malware_app) if idx_item in malware_idx]
     
        
        base_size = 0.1
        s = 5
        if hard_label == True:
           hardlabel = 1
        else:
           hardlabel = 0            
        increase_in_size = base_size * s
        if ignore_optimization == False:
            name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
        else:
            name = "SecSVM"
        
        path = os.path.join(path_base,name)
        if os.path.isdir(path) == False:
            os.mkdir(path)
        
        print("increase_in_size: ",increase_in_size)
        
        serial = False
        if serial == True:
            for app_path in malware_apps_path:
                do_black_box_attack(app_path,action_set,number_of_query,increase_in_size,
                    model_inaccessible_SecSVM,hard_label,malware_detector,path,ignore_optimization)
        else:
            with mp.Pool(processes=config['nprocs_evasion']) as p:
                    p.starmap(do_black_box_attack, zip(malware_apps_path,                                            
                                                        repeat(action_set),
                                                        repeat(number_of_query),
                                                        repeat(increase_in_size),
                                                        repeat(model_inaccessible_SecSVM),
                                                        repeat(hard_label),
                                                        repeat(malware_detector),
                                                        repeat(path),
                                                        repeat(ignore_optimization)))
 
        print("Finish attacking  ...")                 
        if s != 5:
            shutil.rmtree(os.path.join(config['results_dir'],'hosts'))
            shutil.rmtree(os.path.join(config['results_dir'],'postop'))
            os.mkdir(os.path.join(config['results_dir'],'hosts'))
            os.mkdir(os.path.join(config['results_dir'],'postop'))
        else:
            if ignore_optimization == False:
                os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-SecSVM-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
                os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-SecSVM-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
            else:
                os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-SecSVM-ignore_optimization'))
                os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-SecSVM-ignore_optimization'))
           
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
        hard_label = True
        
        if ignore_optimization == False:
            path_base = os.path.join(config['results_dir'],'EvadeDroid/MaMaDroid')
        else:
            path_base = os.path.join(config['results_dir'],'EvadeDroid_ignore_optimization')
        
        
        if os.path.isdir(path_base) == False:
            os.mkdir(path_base)
       
        malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]    
        malware_apps_path = [os.path.join(config['apks_accessible'],'malware',item) for idx_item,item in enumerate(malware_app) if idx_item in malware_idx]
        print("len(malware_apps_path): " ,len(malware_apps_path))
        
        base_size = 0.1
        s = 5
        if hard_label == True:
           hardlabel = 1
        else:
           hardlabel = 0            
        increase_in_size = base_size * s
        if ignore_optimization == False:
            name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
        else:
            name = "MaMaDroid"
        
        path = os.path.join(path_base,name)
        if os.path.isdir(path) == False:
            os.mkdir(path)
        
        print("increase_in_size: ",increase_in_size)
        
        serial = False
        if serial == True:
            for app_path in malware_apps_path:
                do_black_box_attack(app_path,action_set,number_of_query,increase_in_size,
                    model_mamadroid,hard_label,malware_detector,path,ignore_optimization)
        else:
            with mp.Pool(processes=config['nprocs_evasion']) as p:
                    p.starmap(do_black_box_attack, zip(malware_apps_path,                                            
                                                        repeat(action_set),
                                                        repeat(number_of_query),
                                                        repeat(increase_in_size),
                                                        repeat(model_mamadroid),
                                                        repeat(hard_label),
                                                        repeat(malware_detector),
                                                        repeat(path),
                                                        repeat(ignore_optimization)))
 
                         
        print("Finish attacking  ...")
        if s != 5:
            shutil.rmtree(os.path.join(config['results_dir'],'hosts'))
            shutil.rmtree(os.path.join(config['results_dir'],'postop'))
            os.mkdir(os.path.join(config['results_dir'],'hosts'))
            os.mkdir(os.path.join(config['results_dir'],'postop'))
        else:
            
            if ignore_optimization == False:
               os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-MaMaDroid-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
               os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-MaMaDroid-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
            else:
                os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-MaMaDroid-ignore_optimization'))
                os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-MaMaDroid-ignore_optimization'))
                
            
            os.mkdir(os.path.join(config['results_dir'],'hosts'))
            os.mkdir(os.path.join(config['results_dir'],'postop'))
        
        
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on MaMaDroid ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on MaMaDroid ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    
    if reference_attack_on_Drebin == True or reference_attack_on_SecSVM == True or reference_attack_on_AdversarialDeepEnsembleMax == True: 
        model_name = ""
        if reference_attack_on_Drebin == True:
            model = model_inaccessible_Drebin
            model_name = "Drebin"
        elif reference_attack_on_SecSVM == True:
            model = model_inaccessible_SecSVM
            model_name = "SecSVM"            
        elif reference_attack_on_AdversarialDeepEnsembleMax == True:
            model = model_AdversarialDeepEnsembleMax
            model_name = "AdversarialDeepEnsembleMax"
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: reference attack on %s ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" %(model_name))
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: reference attack on %s  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"%(model_name))
        
        detected_malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]
        #malware_apps_name = [item for idx_item,item in enumerate(malware_app) if idx_item in detected_malware_idx]  
        path_fail = os.path.join(config['stored_components'],'malware_apk_fail.p')    
        with open(path_fail, 'rb') as f:
            malware_apk_fail = pickle.load(f)        
        
        path_ref_base = os.path.join(config['results_dir'],'EvadeDroid/ReferenceAttack')
        
        
        if model_name == "Drebin":
            random_attack_path = os.path.join(path_ref_base,'random_attack_drebin.p')
            no_modifiable_features_random_attack = 60
        elif model_name == "SecSVM":
            random_attack_path = os.path.join(path_ref_base,'random_attack_secsvm.p')
            no_modifiable_features_random_attack = 90
        elif model_name == "AdversarialDeepEnsembleMax":
            random_attack_path = os.path.join(path_ref_base,'random_attack_adema.p')
            no_modifiable_features_random_attack = 60
        
        '''
        while True:
            no_modifiable_features_random_attack = int(input())
            if no_modifiable_features_random_attack == 1000:
                break
            else:            
        '''
        y_pred_random_attack = list()
        main_malware_list = dict()
        adv_malware_list = dict()
        if os.path.exists(random_attack_path) == True:            
            with open(random_attack_path , 'rb') as f:
                main_malware_list,adv_malware_list = pickle.load(f)
                apps = [*main_malware_list.keys()]
                no_evasion = len(apps)               
                print("no_evasion:",no_evasion)
                no_malware = len([val for val in detected_malware_idx if malware_app[val] not in malware_apk_fail])
                print("no_malware:",no_malware)               
                
        else:
            cnt = 0
            for i in detected_malware_idx:
                if malware_app[i] in malware_apk_fail:
                    continue
                x_dict = X[malware_app_indices[i]]
                x = model.dict_to_feature_vector(x_dict) 
                if model_name != "AdversarialDeepEnsembleMax":
                    x = x.toarray()
                #_,x_adv_dict = baseline.random_attack(x,len(model.vec.feature_names_),no_modifiable_features_random_attack,model.vec.feature_names_)
                #x_adv = model.dict_to_feature_vector(x_adv_dict) 
                _,x_adv,no_modified_features = baseline.random_attack(x,no_modifiable_features_random_attack,model)              
                
                
                if model_name == "Drebin":
                    y_adv = model.clf.predict(x_adv)[0] 
                elif model_name == "SecSVM":
                    y_adv = model.clf.predict(csr_matrix(x_adv))[0] 
                elif model_name == "AdversarialDeepEnsembleMax":
                    y_adv = model.test_new(x_adv,[1],'label')[0]  
                y_pred_random_attack.append(y_adv)
                print("itr:%d   -   y_adv:%d  -  no_modified_features:%d"%(i,y_adv,no_modified_features))
                cnt += 1
                if y_adv == 0:                  
                    main_malware_list[malware_app[i]] =csr_matrix(x[0])
                    adv_malware_list[malware_app[i]] =csr_matrix(x_adv[0])  
            
            no_evasion = len([val for val in y_pred_random_attack if val == 0])                       
            with open(random_attack_path , 'wb') as f:
                pickle.dump([main_malware_list,adv_malware_list],f) 
              
            print("no_evasion:",no_evasion)
            no_malware = len(y_pred_random_attack)
            print("no_malware:",no_malware)
        
        apps = [*main_malware_list.keys()]
        total_no_added_feature = 0
        import math
        max_no_fe = 0
        for key in apps:
            total_no_added_feature += sum(adv_malware_list[key].toarray()[0])-sum(main_malware_list[key].toarray()[0])            
            if max_no_fe < sum(adv_malware_list[key].toarray()[0])-sum(main_malware_list[key].toarray()[0]):
                    max_no_fe = sum(adv_malware_list[key].toarray()[0])-sum(main_malware_list[key].toarray()[0])
        print("max:",max_no_fe)
        if no_evasion != 0:
            avg_no_added_feature = total_no_added_feature/no_evasion
        
            total_no_added_feature = 0
            for key in apps:
                total_no_added_feature += ((sum(adv_malware_list[key].toarray()[0])-sum(main_malware_list[key].toarray()[0]))-avg_no_added_feature)**2
            std_no_added_feature = math.sqrt(total_no_added_feature/(no_evasion-1))
                
        ER_random_attack = (no_evasion/no_malware)*100          
        print("ER_random_attack (%s): %f "%(model_name,ER_random_attack))  
        if no_evasion != 0:
            print("avg_no_added_feature (%s): %f + %f"%(model_name,avg_no_added_feature,std_no_added_feature))
             
        print('.............................')
        
        if model_name == "Drebin" or model_name == "SecSVM":
            if model_name == "Drebin":
                pk_feature_path = os.path.join(path_ref_base,'pk_feature_drebin.p')
            elif model_name == "SecSVM":
                pk_feature_path = os.path.join(path_ref_base,'pk_feature_secsvm.p')
            
            no_modifiable_features_pk_attack = 100
            y_pred_pk_attack = list()
            main_malware_list = dict()
            adv_malware_list = dict()
            print("strart pk_feature attack ... ")
            
            if os.path.exists(pk_feature_path) == True:            
                with open(pk_feature_path , 'rb') as f:
                    main_malware_list,adv_malware_list = pickle.load(f)
                    apps = [*main_malware_list.keys()]
                    no_evasion = len(apps)               
                    print("no_evasion:",no_evasion)
                    no_malware = len([val for val in detected_malware_idx if malware_app[val] not in malware_apk_fail])
                    print("no_malware:",no_malware)               
                    
            else:
                for i in detected_malware_idx:
                
                    if malware_app[i] in malware_apk_fail:
                        continue
                    
                    x_dict = X[malware_app_indices[i]]
                    x = model.dict_to_feature_vector(x_dict) 
                    x = x.toarray()
                    _,x_adv,no_modified_features = baseline.pk_feature_attack(x,no_modifiable_features_pk_attack,model)               
                    if model_name != "SecSVM":
                        y_adv = model.clf.predict(x_adv)[0] 
                    else:
                        y_adv = model.clf.predict(csr_matrix(x_adv))[0] 
                    y_pred_pk_attack.append(y_adv)
                    if y_adv == 0:                  
                        main_malware_list[malware_app[i]] =csr_matrix(x[0])
                        adv_malware_list[malware_app[i]] =csr_matrix(x_adv[0])          
               
                
                
                with open(pk_feature_path , 'wb') as f:
                    pickle.dump([main_malware_list,adv_malware_list],f)
                no_evasion = len([val for val in y_pred_pk_attack if val == 0])
                print("no_evasion:",no_evasion)
                no_malware = len(y_pred_pk_attack)
                print("no_malware:",no_malware)
            
            apps = [*main_malware_list.keys()]
            total_no_added_feature = 0
            import math
            
            for key in apps:
                total_no_added_feature += sum(adv_malware_list[key].toarray()[0])-sum(main_malware_list[key].toarray()[0])   
                
            avg_no_added_feature = total_no_added_feature/no_evasion
            
            total_no_added_feature = 0
            for key in apps:
                total_no_added_feature += ((sum(adv_malware_list[key].toarray()[0])-sum(main_malware_list[key].toarray()[0]))-avg_no_added_feature)**2
            std_no_added_feature = math.sqrt(total_no_added_feature/(no_evasion-1))
                    
            ER_pk_feature_attack = (no_evasion/no_malware)*100          
            print("ER_pk_feature_attack (%s): %f "%(model_name,ER_pk_feature_attack))  
            print("avg_no_added_feature (%s): %f + %f"%(model_name,avg_no_added_feature,std_no_added_feature))
            
            print('.............................')
        
        #reference_attack_on_AdversarialDeepEnsembleMax = False
        if model_name == "AdversarialDeepEnsembleMax":
            #model_name = "AdversarialDeepEnsembleMax"
            utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: reference attack on %s ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" %(model_name))
            print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: reference attack on %s  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"%(model_name))
            from attacker.attack_manager import AttackManager
            method = "pgdl1"
            targeted_model_name = "adema"#"basic_dnn"#"adema"
            scenario = "white-box"
            is_real_sample = False            
            attack_mgr = AttackManager(method, scenario, targeted_model_name,is_real_sample)
            attack_mgr.attack()        
            utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: reference attack on %s ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"%(model_name))
            print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: reference attack on %s  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"%(model_name))
        
        
        y_pred_pk_attack = list()
        cnt = 0
        main_malware_list = dict()
        adv_malware_list = dict()
        adv_malware_query = dict()       
        no_malware = 0
        print("strart sparse_sr attack ... ")
        
        if model_name == "Drebin":
            sparse_sr_path = os.path.join(path_ref_base,'sparse_sr_drebin.p')
        elif model_name == "SecSVM":
            sparse_sr_path = os.path.join(path_ref_base,'sparse_sr_secsvm.p')
        elif model_name == "AdversarialDeepEnsembleMax":
            sparse_sr_path = os.path.join(path_ref_base,'sparse_sr_adema.p')
        
        if os.path.exists(sparse_sr_path) == True:            
            with open(sparse_sr_path , 'rb') as f:
                main_malware_list,adv_malware_list,adv_malware_query = pickle.load(f)
                apps = [*main_malware_list.keys()]
                no_evasion = len(apps)
                print("len(apps):",len(apps))               
                no_malware = len([val for val in detected_malware_idx if malware_app[val] not in malware_apk_fail])
                print("no_malware:",no_malware)
        else:
            
            for i in detected_malware_idx:                
                
                if malware_app[i] in malware_apk_fail:
                    continue                                
                '''
                if malware_app[i] != 'com.android.yizhitong.jiazhuangtong.apk' and malware_app[i] != 'com.tencent.qqgame.apk':
                    continue     
                '''
                x_dict = X[malware_app_indices[i]]
                x = model.dict_to_feature_vector(x_dict) 
                if model_name != "AdversarialDeepEnsembleMax":
                    x = x.toarray()
                print("sum x_malware",sum(x[0]))
                _,x_adv,no_query,no_modified_features = baseline.create_adversarial_example_sparse_RS(x[0],model,model_name_val=model_name,q=100,k=100)
                #x_adv = model.dict_to_feature_vector(x_adv_dict)
                print("sum x_adv_malware",sum(x_adv[0]))
                if model_name == "SecSVM":
                    y_adv = model.clf.predict(csr_matrix(x_adv))[0]              
                elif model_name == "Drebin":
                    y_adv = model.clf.predict(x_adv)[0]              
                elif model_name == "AdversarialDeepEnsembleMax":
                    y_adv = model.test_new(x_adv,[1],'label')[0]  
                y_pred_pk_attack.append(y_adv)
                cnt += 1
                print("ctn:%d - y_adv: %s  - q:%d  - no_modified_features:%d"%(cnt,str(y_adv),no_query,no_modified_features))
                if y_adv == 0:
                    main_malware_list[malware_app[i]] =csr_matrix(x[0])
                    adv_malware_list[malware_app[i]] =csr_matrix(x_adv[0])
                    adv_malware_query[malware_app[i]] =no_query               
                   
                    with open(sparse_sr_path , 'wb') as f:
                        pickle.dump([main_malware_list,adv_malware_list,adv_malware_query],f)
                    
                print('--------------')            
            no_malware = len(y_pred_pk_attack)
            no_evasion = len([val for val in y_pred_pk_attack if val == 0])
        
        apps = [*main_malware_list.keys()]
        total_no_added_feature = 0
        import math
        for key in apps:
            total_no_added_feature += sum(adv_malware_list[key].toarray()[0])-sum(main_malware_list[key].toarray()[0])
        avg_no_added_feature = total_no_added_feature/no_evasion
        
        total_no_added_feature = 0
        for key in apps:
            total_no_added_feature += ((sum(adv_malware_list[key].toarray()[0])-sum(main_malware_list[key].toarray()[0]))-avg_no_added_feature)**2
        std_no_added_feature = math.sqrt(total_no_added_feature/(no_evasion-1))
   
        total_query = 0       
        for key in adv_malware_query.keys():
            total_query += adv_malware_query[key]
        avg_query = total_query/no_evasion
        ER_sparse_rs_attack = (no_evasion/no_malware)*100  
        print("ER_sparse_rs_attack (%s): %f "%(model_name,ER_sparse_rs_attack))
        print("Qvg Query of sparse_rs_attack (%s): %f "%(model_name,avg_query))
        print("avg_no_added_feature (%s): %f + %f"%(model_name,avg_no_added_feature,std_no_added_feature))
       
        
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
            
        
        base_path = os.path.join(config['apks_accessible'],'vt_engines',malware_detector)
        malware_apps = os.listdir(base_path)
        
        if malware_name != 'None':
            malware_apps = [malware_name]
       
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
        name = "result_%s"%(malware_detector)
        path = os.path.join(path_base,name)
        if os.path.isdir(path) == False:
            os.mkdir(path)
        
        print("increase_in_size: ",increase_in_size)
        empty_model = []
        for app_path in malware_apps_path:
                do_black_box_attack(app_path,action_set,number_of_query,increase_in_size,
                    empty_model,hard_label,malware_detector,path,ignore_optimization)
        print("Finish attacking  ...")                 
        '''
        os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts_%s'%(malware_detector)))
        os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop_%s'%(malware_detector)))
        os.mkdir(os.path.join(config['results_dir'],'hosts'))
        os.mkdir(os.path.join(config['results_dir'],'postop'))
        '''
        
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on VirusTotal ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on VirusTotal ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        
        
    if evasion_attack_AdversarialDeepEnsembleMax == True: #adema: hardened ensemble-based DNN incorporating adversarial training with a mixture of attacks
        
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: evasion attack on AdversarialDeepEnsembleMax ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: evasion attack on AdversarialDeepEnsembleMax  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
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
        malware_detector = "AdversarialDeepEnsembleMax"
        hard_label = True   
        
        if ignore_optimization == False:
             path_base = os.path.join(config['results_dir'],'EvadeDroid/AdversarialDeepEnsembleMax')
        else:
            path_base = os.path.join(config['results_dir'],'EvadeDroid_ignore_optimization')
        if os.path.isdir(path_base) == False:
            os.mkdir(path_base)           
        malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]  
        malware_apps_path = [os.path.join(config['apks_accessible'],'malware',item) for idx_item,item in enumerate(malware_app) if idx_item in malware_idx]
        print("len(malware_apps_path): " ,len(malware_apps_path))              
        s = 5
        if hard_label == True:
           hardlabel = 1
        else:
           hardlabel = 0            
        increase_in_size = base_size * s
        if ignore_optimization == False:
            name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
        else:
            name = "AdversarialDeepEnsembleMax"
        
        path = os.path.join(path_base,name)
        if os.path.isdir(path) == False:
            os.mkdir(path)        
        print("increase_in_size: ",increase_in_size)        
        serial = False
        if serial == True:
            for app_path in malware_apps_path:
                do_black_box_attack_for_DNN(app_path,action_set,number_of_query,increase_in_size,
                    hard_label,malware_detector,path,ignore_optimization)
        else:
            with mp.Pool(processes=config['nprocs_evasion']) as p:
                    p.starmap(do_black_box_attack_for_DNN, zip(malware_apps_path,                                            
                                                        repeat(action_set),
                                                        repeat(number_of_query),
                                                        repeat(increase_in_size),                                                        
                                                        repeat(hard_label),
                                                        repeat(malware_detector),
                                                        repeat(path),
                                                        repeat(ignore_optimization)))                         
        print("Finish attacking  ...")
        if s != 5:
            shutil.rmtree(os.path.join(config['results_dir'],'hosts'))
            shutil.rmtree(os.path.join(config['results_dir'],'postop'))
            os.mkdir(os.path.join(config['results_dir'],'hosts'))
            os.mkdir(os.path.join(config['results_dir'],'postop'))
        else:
            if ignore_optimization == False:
                os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-AdversarialDeepEnsembleMax-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
                os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-AdversarialDeepEnsembleMax-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,hardlabel)))
            else:
                os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-AdversarialDeepEnsembleMax-ignore_optimization'))
                os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-AdversarialDeepEnsembleMax-ignore_optimization'))         
            

            os.mkdir(os.path.join(config['results_dir'],'hosts'))
            os.mkdir(os.path.join(config['results_dir'],'postop'))
        
        
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on AdversarialDeepEnsembleMax ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: evasion attack on AdversarialDeepEnsembleMax ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    
    
    if check_transferability == True:       
        if traget_model_name == 'AdversarialDeepEnsembleMax':
            traget_model = model_AdversarialDeepEnsembleMax
        elif traget_model_name == 'Drebin' or  traget_model_name == 'SecSVM':
            if traget_model_name == 'SecSVM':
                traget_model = models.SecSVM("SecSVM",False, config['X_dataset_inaccessible'], config['Y_dataset_inaccessible'],
                                      config['meta_inaccessible'], num_features=None,
                                      secsvm_k=0.2, secsvm=False, secsvm_lr=0.0001,
                                      secsvm_batchsize=1024, secsvm_nepochs=20, seed_model=None)
            else:
                traget_model = models.SVM("Drebin", False, config['X_dataset_inaccessible'], config['Y_dataset_inaccessible'],
                                  config['meta_inaccessible'],num_features = None,append = None)
        
            if os.path.exists(traget_model.model_name):
                traget_model = models.load_from_file(traget_model.model_name)
            else:
                print("Generate Drebin model ...")
                traget_model.generate() 
        elif traget_model_name == 'MaMaDroid':
            from mamadroid import mamadroid, MaMaStat            
            model_inaccessible = models.SVM("Drebin", False, config['X_dataset_inaccessible'], config['Y_dataset_inaccessible'],
                                      config['meta_inaccessible'])
            model_inaccessible = models.load_from_file(model_inaccessible.model_name)
            path = os.path.join(config['mamadroid'],'Features/Families/dataset_inaccessible.p')    
            traget_model = models.SVM("MaMaDroid", False, path, model_inaccessible.y_train,
                                 model_inaccessible.m_train)  
                     
            if os.path.exists(traget_model.model_name):
                 traget_model = models.load_from_file(traget_model.model_name)
            else:
                 traget_model.generate_mamadroid(no_training_sample=11050) 
        
        y_pred = list()        
        base_path = os.path.join(config['results_dir'],'EvadeDroid',substitute,'result-noquery_20-size_0.500000-hardlabel_0')
        apk_names = os.listdir(base_path)
        no_adv_example = 0
        for app in apk_names:
            apk_info_path = os.path.join(base_path,app)
            with open(apk_info_path , 'rb') as f:
                apk = pickle.load(f)
            if apk.adv_malware_label == 0:                
                if apk.app_name == "alfatih.bedroomidea.apk":
                    continue
                if apk.app_name == "abujanda.upayback.com.apk":
                    continue
                post_op_host = os.path.join(config['results_dir'],'postop-'+substitute+'-noquery_20-size_0.500000-hardlabel_0',apk.app_name)
                malware_dict = drebin.get_features(post_op_host) 
                x_malware = traget_model.dict_to_feature_vector(malware_dict) 
                if traget_model_name == 'AdversarialDeepEnsembleMax':                    
                    y_pred_app = model_AdversarialDeepEnsembleMax.test_new(x_malware,[1],'label')[0]                  
                elif traget_model_name == 'Drebin' or  traget_model_name == 'SecSVM':
                    y_pred_app = traget_model.clf.predict(x_malware)[0]
                elif traget_model_name == 'MaMaDroid':
                    db = "sample_" + apk.app_name.replace('.','_')
                    mamadroid.api_sequence_extraction([post_op_host],db)
                    _app_dir = config['mamadroid']
                    no_finished_apps = len(os.listdir(os.path.join(_app_dir,'graphs',db)))
                    if no_finished_apps == 0: 
                        print("Remove transformation because of failing in creating api call graph")                         
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
                    y_pred_app = model.clf.predict(x_manipulated_mamadroid)[0]
                    
                print("y_pred_app: ", y_pred_app)
                y_pred.append(abs(y_pred_app-1))
                no_adv_example += 1
                ER_temp = (sum(y_pred)/no_adv_example)*100 
                print("substitute: %s on traget_model: %s- sum_y: %d - no_adv_example: %d - ER: %s"%(substitute,traget_model_name,sum(y_pred),no_adv_example,str(ER_temp) + "%"))
        ER = (sum(y_pred)/no_adv_example)*100 
        print("ER: ",ER)           
        print("ER (%s on %s): %s"%(substitute,traget_model_name,str(ER) + "%"))
        
    
    if adversarial_retraining == True:         
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: adversarial retraining ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ Start: adversarial retraining  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        X_dataset_inaccessible_adv_training_path = os.path.join(config['features_inaccessible'],'inaccessible-dataset-X-adv-training.json')
        if os.path.exists(X_dataset_inaccessible_adv_training_path) == False:
        
            action_set_path = os.path.join(config['stored_components'],'action_set.p')        
            with open(action_set_path, 'rb') as f:
                action_set = pickle.load(f) 
            for item in action_set.keys():
                organ_path = action_set[item] 
                with open(organ_path, 'rb') as f:
                    organ = pickle.load(f) 
                action_set[item]  = organ        
            number_of_query = 20
            increase_in_size = 0.5            
            hard_label = False      
            malware_detector = "Drebin"
            path_base = os.path.join(config['results_dir'],'EvadeDroid_adversarial_retraining')
            if os.path.isdir(path_base) == False:
                os.mkdir(path_base)       
           
            inaccessible_malware_app = os.listdir(os.path.join(config['apks_inaccessible'],'malware'))
            malware_apps_path = [os.path.join(config['apks_inaccessible'],'malware',item) for idx_item,item in enumerate(inaccessible_malware_app)]
            
            name = "Drebin"
            path = os.path.join(path_base,name)
            if os.path.isdir(path) == False:
                os.mkdir(path)      
           
            
            serial = True
            if serial == True:
                for app_path in malware_apps_path:
                    do_black_box_attack(app_path,action_set,number_of_query,increase_in_size,
                        model_inaccessible_Drebin,hard_label,malware_detector,path,ignore_optimization,no_ae_malware = 100)
            else:
                with mp.Pool(processes=config['nprocs_evasion']) as p:
                        p.starmap(do_black_box_attack, zip(malware_apps_path,                                            
                                                            repeat(action_set),
                                                            repeat(number_of_query),
                                                            repeat(increase_in_size),
                                                            repeat(model_inaccessible_Drebin),
                                                            repeat(hard_label),
                                                            repeat(malware_detector),
                                                            repeat(path),
                                                            repeat(ignore_optimization),
                                                            repeat(no_ae_malware = 100)))
     
            print("Finish generating adversarial training  ...")               
            '''
            os.rename(os.path.join(config['results_dir'],'hosts'),os.path.join(config['results_dir'],'hosts-Drebin-adversarial_retraining'))
            os.rename(os.path.join(config['results_dir'],'postop'),os.path.join(config['results_dir'],'postop-Drebin-adversarial_retraining'))
            os.mkdir(os.path.join(config['results_dir'],'hosts'))
            os.mkdir(os.path.join(config['results_dir'],'postop')) 
            '''
            #Create adversarial retraining dataset
            path = config['X_dataset_inaccessible']
            with open(path,'r') as file:
                X_dataset_inaccessible = json.load(file)
            
            path = config['meta_inaccessible']
            with open(path,'r') as file:
                meta_dataset_inaccessible = json.load(file)
            
            print("len(X_dataset_inaccessible)",len(X_dataset_inaccessible))
            print("len(meta_dataset_inaccessible)",len(meta_dataset_inaccessible))
            
            base_path = os.path.join(config['results_dir'],'EvadeDroid_adversarial_retraining/%s'%(malware_detector))  
            apk_name = os.listdir(base_path)  
            cnt = 0
            for app in apk_name:        
                apk_info_path = os.path.join(base_path,app)
                with open(apk_info_path , 'rb') as f:
                    apk = pickle.load(f)
                if apk.adv_malware_label == 0 and apk.number_of_queries > 0:                    
                    idx_adversarial_trainin = [idx for idx,val in enumerate(meta_dataset_inaccessible) if apk.app_name == val['pkg_name']+'.apk'][0]
                    X_dataset_inaccessible[idx_adversarial_trainin] = apk.new_adv_dict                                   
            
            with open(X_dataset_inaccessible_adv_training_path,'w') as file:
                json.dump(X_dataset_inaccessible,file)
        
            
        model_inaccessible_Drebin_robust = models.SVM("Drebin-Robust", False, X_dataset_inaccessible_adv_training_path, config['Y_dataset_inaccessible'],
                                  config['meta_inaccessible'],num_features = None,append = None)
        
        if os.path.exists(model_inaccessible_Drebin_robust.model_name):
            model_inaccessible_Drebin_robust = models.load_from_file(model_inaccessible_Drebin_robust.model_name)
        else:
            print("model_inaccessible_Drebin.model_name:",model_inaccessible_Drebin_robust.model_name)
            print("Generate Drebin-Robust model ...")
            model_inaccessible_Drebin_robust.generate()           
        
        y_pred = list()
        for app_index in malware_app_indices:
            malware_dict = X[app_index]
            x_malware = model_inaccessible_Drebin_robust.dict_to_feature_vector(malware_dict) 
            y_pred_app = model_inaccessible_Drebin_robust.clf.predict(x_malware)   
            y_pred.append(y_pred_app)
        ACC = (sum(y_pred)/len(malware_app_indices))*100            
        print("ACC (DREBIN):" + str(ACC[0]) + "%")
        
        print("---------------------------------")
        malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]
        detected_apps_name = [item for idx_item,item in enumerate(malware_app) if idx_item in malware_idx]
        detected_apps_features = dict()
        
        Drebin_AEs_AT_experiment_path = os.path.join(config['features_inaccessible'],'Drebin_AEs_for_AT_experiment.json')
        if os.path.exists(Drebin_AEs_AT_experiment_path) == False:
            base_path = os.path.join(config['results_dir'],'EvadeDroid/Drebin/result-noquery_20-size_0.500000-hardlabel_0') 
            apk_name = os.listdir(base_path)  
            cnt = 0
            for app in apk_name:        
                apk_info_path = os.path.join(base_path,app)
                with open(apk_info_path , 'rb') as f:
                    apk = pickle.load(f)
                if apk.adv_malware_label == 0 and apk.number_of_queries > 0:  
                    if apk.app_name in detected_apps_name:                    
                        malware_app_path = os.path.join(config['results_dir'],'postop-Drebin-noquery_20-size_0.500000-hardlabel_0',apk.app_name)
                        malware_dict = drebin.get_features(malware_app_path)
                        x_malware = model_inaccessible_Drebin.dict_to_feature_vector(malware_dict) 
                        y_pred_app = model_inaccessible_Drebin.clf.predict(x_malware)
                        if y_pred_app == 0:
                            detected_apps_features[apk.app_name] = malware_dict                        
                            with open(Drebin_AEs_AT_experiment_path,'w') as file:
                                json.dump(detected_apps_features,file)
                            print("len(detected_apps_features):",len(detected_apps_features))
                            if len(detected_apps_features) == 50:
                                break
        else:
            with open(Drebin_AEs_AT_experiment_path,'r') as file:
                detected_apps_features = json.load(file)            
        y_pred = list()
        for malware_app_key in detected_apps_features.keys():   
            malware_dict = detected_apps_features[malware_app_key]
            x_malware = model_inaccessible_Drebin_robust.dict_to_feature_vector(malware_dict) 
            y_pred_app = model_inaccessible_Drebin_robust.clf.predict(x_malware)   
            y_pred.append(y_pred_app)
        ACC = (sum(y_pred)/len(detected_apps_features))*100            
        print("ACC on AEs (Augmented-Drebin):" + str(ACC[0]) + "%")
        
        y_pred = list()
        for malware_app_key in detected_apps_features.keys():   
            malware_dict = detected_apps_features[malware_app_key]
            x_malware = model_inaccessible_Drebin.dict_to_feature_vector(malware_dict) 
            y_pred_app = model_inaccessible_Drebin.clf.predict(x_malware)   
            y_pred.append(y_pred_app)
        ACC = (sum(y_pred)/len(detected_apps_features))*100            
        print("ACC on AEs (Drebin):" + str(ACC[0]) + "%")
        print("---------------------------------")
        
        X_test_set_path = os.path.join(config['features_accessible'],'accessible-dataset-X.json')
        with open(X_test_set_path,'r') as file:
            X_test_set = json.load(file)
        
        Y_test_set_path = os.path.join(config['features_accessible'],'accessible-dataset-Y.json')
        with open(Y_test_set_path,'r') as file:
            Y_test_set = json.load(file)
            
        print("no. malware apps in test set:",len([val for val in Y_test_set if val == 1]))
        print("no. benign apps in test set:",len([val for val in Y_test_set if val == 0]))
        
        y_pred = list()
        for app_dict in X_test_set:               
            x_app = model_inaccessible_Drebin_robust.dict_to_feature_vector(app_dict) 
            y_pred_app = model_inaccessible_Drebin_robust.clf.predict(x_app)   
            y_pred.append(y_pred_app)
        
        tn, fp, fn, tp = confusion_matrix(Y_test_set,y_pred).ravel()
        
        print("TPR (Augmented-Drebin) on set",(tp/(tp+fn))*100)
        print("FPR (Augmented-Drebin) on set",(fp/(fp+tn))*100)
        
        y_pred = list()
        for app_dict in X_test_set:               
            x_app = model_inaccessible_Drebin.dict_to_feature_vector(app_dict) 
            y_pred_app = model_inaccessible_Drebin.clf.predict(x_app)   
            y_pred.append(y_pred_app)
        
        tn, fp, fn, tp = confusion_matrix(Y_test_set,y_pred).ravel()
        
        print("TPR (Drebin) on set",(tp/(tp+fn))*100)
        print("FPR (Drebin) on set",(fp/(fp+tn))*100)
        
        return
        
        print("---------------------------------")
        action_set_path = os.path.join(config['stored_components'],'action_set.p')        
        with open(action_set_path, 'rb') as f:
            action_set = pickle.load(f) 
        for item in action_set.keys():
            organ_path = action_set[item] 
            with open(organ_path, 'rb') as f:
                organ = pickle.load(f) 
            action_set[item]  = organ        
        number_of_query = 20
        increase_in_size = 0.5            
        hard_label = False      
        malware_detector = "DrebinRobust"
        path_base = os.path.join(config['results_dir'],'EvadeDroid')
        if os.path.isdir(path_base) == False:
            os.mkdir(path_base)       
       
        #accessible_malware_app = os.listdir(os.path.join(config['apks_accessible'],'malware'))
        target_apps=[*detected_apps_features.keys()]
        malware_apps_path = [os.path.join(config['apks_accessible'],'malware',val) for val in target_apps]
        
        name = "DrebinRobust"
        path = os.path.join(path_base,name)
        if os.path.isdir(path) == False:
            os.mkdir(path)      
       
        
        serial = True
        if serial == True:
            for app_path in malware_apps_path:
                do_black_box_attack(app_path,action_set,number_of_query,increase_in_size,
                    model_inaccessible_Drebin_robust,hard_label,malware_detector,path,ignore_optimization,no_ae_malware = 100)
        else:
            with mp.Pool(processes=config['nprocs_evasion']) as p:
                    p.starmap(do_black_box_attack, zip(malware_apps_path,                                            
                                                        repeat(action_set),
                                                        repeat(number_of_query),
                                                        repeat(increase_in_size),
                                                        repeat(model_inaccessible_Drebin_robust),
                                                        repeat(hard_label),
                                                        repeat(malware_detector),
                                                        repeat(path),
                                                        repeat(ignore_optimization),
                                                        repeat(no_ae_malware = 100)))
 
        print("Finish generating adversarial training  ...")
        
        
        utils.perform_logging("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: adversarial retraining ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~ End: adversarial retraining ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")


def do_black_box_attack(app_path,action_set,number_of_query,increase_in_size,
                        model_inaccessible,hard_label,malware_detector,path,ignore_optimization,no_ae_malware = None):    
        
    path_fail = os.path.join(config['stored_components'],'malware_apk_fail.p')    
    with open(path_fail, 'rb') as f:
        malware_apk_fail = pickle.load(f)
    if os.path.basename(app_path) in malware_apk_fail:
        print("app is corrupt")
        return
    
    #path_base = os.path.join(config['results_dir'],'EvadeDroid/Drebin','result-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,(hard_label * 1)))
    if malware_detector == "Drebin" or malware_detector == "SecSVM" or malware_detector == "MaMaDroid":
        if ignore_optimization == False and no_ae_malware == None:
            path_base = os.path.join(config['results_dir'],'EvadeDroid/%s'%(malware_detector),'result-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,(hard_label * 1)))
        elif ignore_optimization == True:
            path_base = os.path.join(config['results_dir'],'EvadeDroid_ignore_optimization/%s'%(malware_detector))
        elif no_ae_malware != None:
            path_base = os.path.join(config['results_dir'],'EvadeDroid_adversarial_retraining/%s'%(malware_detector))
    elif malware_detector == "DrebinRobust":
        path_base = os.path.join(config['results_dir'],'EvadeDroid/%s'%(malware_detector))
        malware_detector = "Drebin"
    else:        
        name = "result_%s"%(malware_detector)
        path_base = os.path.join(config['results_dir'],'EvadeDroid/VirusTotal/%s'%(name))
    #path_base_temp = path_base +'/back'
    apps_checked = os.listdir(path_base)
    
    if no_ae_malware != None:
        no_generated_ae = 0
        for app in apps_checked:       
            apk_info_path = os.path.join(path_base,app)
            with open(apk_info_path , 'rb') as f:
                apk = pickle.load(f)       
            if apk.adv_malware_label == 0 and apk.intact_due_to_soot_error == 0:
                no_generated_ae += 1
        if no_generated_ae >= no_ae_malware:
            return    
    
    if os.path.splitext(os.path.basename(app_path))[0] +'.p' in apps_checked:
        print('%s has been already checked'%(os.path.basename(app_path)))
        return    
    
    if os.path.splitext(os.path.basename(app_path))[0] +'.apk.json' in apps_checked:
        print('%s has been already checked'%(os.path.basename(app_path)))
        return    
    
    print("----------------------------------------------------")
    no_finished_apps = len(os.listdir(path))
    print("no_finished_apps = " + str(no_finished_apps))
    
    malware = app_path#os.path.join(config['apks_accessible'],'malware',malware_app[i])
    
    apk = evasion.generate_adversarial_example(malware, action_set, number_of_query, 
                                         increase_in_size, model_inaccessible, 
                                         hard_label, malware_detector,ignore_optimization)
    if malware_detector == "Total":
        print('app name: %s  -  detection status:%s'%(os.path.basename(malware),apk))
    else:        
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
   
    
    if malware_detector == "Total":
        apk_info_path = os.path.join(path,os.path.basename(malware) +'.json')
        with open(apk_info_path,'w') as outfile:
            json.dump(apk,outfile,indent = 4)
    else:
        #apk_info_path = os.path.join(path,apk.app_name.replace('.apk','.p'))
        apk_info_path = os.path.join(path,os.path.splitext(apk.app_name)[0] +'.p')
        with open(apk_info_path , 'wb') as f:
            pickle.dump(apk,f)
            print("copy done: %s"%(apk_info_path))
        
    
    print("----------------------------------------------------")   
    
def do_black_box_attack_for_DNN(app_path,action_set,number_of_query,increase_in_size,
                        hard_label,malware_detector,path,ignore_optimization):  
    
    print("app_path: ", app_path)    
    path_fail = os.path.join(config['stored_components'],'malware_apk_fail.p')    
    with open(path_fail, 'rb') as f:
        malware_apk_fail = pickle.load(f)
    if os.path.basename(app_path) in malware_apk_fail:
        print("app is corrupt")
        return   
    
    if ignore_optimization == False:
        path_base = os.path.join(config['results_dir'],'EvadeDroid/%s'%(malware_detector),'result-noquery_%d-size_%f-hardlabel_%d'%(number_of_query,increase_in_size,(hard_label * 1)))
    else:
        path_base = os.path.join(config['results_dir'],'EvadeDroid_ignore_optimization/%s'%(malware_detector))
    
    apps_checked = os.listdir(path_base)
    
    
    if os.path.splitext(os.path.basename(app_path))[0] +'.p' in apps_checked:
        print("app_path: ",app_path)
        print('%s has been already checked'%(os.path.basename(app_path)))
        return  
    
    print("----------------------------------------------------")
    no_finished_apps = len(os.listdir(path))
    print("no_finished_apps = " + str(no_finished_apps))
    
    malware = app_path#os.path.join(config['apks_accessible'],'malware',malware_app[i])
    
    apk = evasion.generate_adversarial_example(malware, action_set, number_of_query, 
                                         increase_in_size, model_AdversarialDeepEnsembleMax, 
                                         hard_label, malware_detector,ignore_optimization)
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
    parser = argparse.ArgumentParser()    
    parser.add_argument('--download_samples', default=False, type = bool)
    parser.add_argument('--initial_check_apks', default=False, type = bool)
    parser.add_argument('--accessible_inaccessible_datset_preparation', default=False, type = bool)
    parser.add_argument('--mamadroid_feature_extraction', default=False, type = bool)
    parser.add_argument('--n_gram_feature_extraction', default=False, type = bool)
    parser.add_argument('--create_action_set', default=False, type = bool)
    parser.add_argument('--roc_curve', default=False, type = bool)
    parser.add_argument('--create_Drebin', default=False, type = bool)
    parser.add_argument('--create_SecSVM', default=False, type = bool)
    parser.add_argument('--evasion_attack_Drebin', default=False, type = bool)
    parser.add_argument('--evasion_attack_SecSVM', default=False, type = bool)
    parser.add_argument('--reference_attack_on_Drebin', default=False, type = bool)
    parser.add_argument('--reference_attack_on_SecSVM', default=False, type = bool)
    parser.add_argument('--mamadroid_malware_feature_extraction', default=False, type = bool)
    parser.add_argument('--create_MaMaDroid', default=False, type = bool)
    parser.add_argument('--evasion_attack_MaMaDroid', default=False, type = bool)
    parser.add_argument('--evasion_attack_vt', default=False, type = bool)
    parser.add_argument('--vt_engine', default='Total',type = str)
    parser.add_argument('--create_AdversarialDeepEnsembleMax', default=False, type = bool)
    parser.add_argument('--evasion_attack_AdversarialDeepEnsembleMax', default=False, type = bool)
    parser.add_argument('--check_transferability', default=False, type = bool)
    parser.add_argument('--substitute', default='SecSVM', type = str)
    parser.add_argument('--traget_model_name', default='Drebin', type = str)
    parser.add_argument('--ignore_optimization', default=False, type = bool)
    parser.add_argument('--reference_attack_on_AdversarialDeepEnsembleMax', default=False, type = bool)
    parser.add_argument('--adversarial_retraining', default=False, type = bool)
    parser.add_argument('--malware_name', default='None',type = str)
    
    args = parser.parse_args()
    main(args)
    