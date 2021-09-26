# -*- coding: utf-8 -*-
"""
Baseline evasion attacks
"""

import random
import numpy as np
import os
import pickle
from settings import config
import black_box_attack.models as models
import json

def random_attack(x,no_features,no_modifiable_features,features):     
    index_candidate_features = [idx for idx,val in enumerate(x[0]) if val == 0]
    features_rand = random.sample(index_candidate_features,no_modifiable_features)
    x_dict = dict()
    for f in range(0,len(features)):
        if f in features_rand:
            x[0][f] = 1 
        if x[0][f] == 1:
            x_dict[features[f]] = 1
    return x,x_dict

def pk_attack(x,no_modifiable_features,weights,features,model):
    abs_weights=np.absolute(weights)
    #sort_abs_weight=-np.sort(-abs_weights)
    sort_index=np.argsort(-abs_weights)  
    cnt = 0
    x_dict = dict()    
    for x_k in sort_index[0]:
        if cnt != no_modifiable_features and x[0][x_k] == 0 and weights[0][x_k]<0:
            x[0][x_k] = 1 
            cnt += 1            
            x_dict[features[x_k]] = 1            
        
        if x[0][x_k] == 1:
            x_dict[features[x_k]] = 1 
        
        
    return x,x_dict,cnt


def secsvm():
    path = os.path.join(config['features'] , 'sub_dataset/', 'accessible_malware_index.p')
    with open(path,'rb') as f:
        malware_app = pickle.load(f) 
    
    X_filename = os.path.join(config['features'] , 'sub_dataset/', 'sub_dataset-X.json')   
    with open(X_filename, 'rt') as f:
        X = json.load(f)   
    malware_app_indices = [item for item in malware_app.values()]
    malware_app = [item for item in malware_app.keys()]
    
    model = models.SecSVM("SecSVM",False, config['X_dataset_inaccessible'], config['Y_dataset_inaccessible'],
                              config['meta_inaccessible'], num_features=None,
                              secsvm_k=0.2, secsvm=False, secsvm_lr=0.0001,
                              secsvm_batchsize=1024, secsvm_nepochs=20, seed_model=None)
    
    if os.path.exists(model.model_name):
        model = models.load_from_file(model.model_name)
    else:        
        model.generate()       
    
    y_pred = list()
    for app_index in malware_app_indices:
        malware_dict = X[app_index]
        x_malware = model.dict_to_feature_vector(malware_dict) 
        y_pred_app = model.clf.predict(x_malware)   
        y_pred.append(y_pred_app[0])
    DR = (sum(y_pred)/len(malware_app_indices))*100
    print("DR: ",DR)
    
    detected_malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]
    #malware_apps_name = [item for idx_item,item in enumerate(malware_app) if idx_item in detected_malware_idx]  
    path_fail = os.path.join(config['stored_components'],'malware_apk_fail.p')    
    with open(path_fail, 'rb') as f:
       malware_apk_fail = pickle.load(f)
    y_pred_pk_attack = list()
    no_modified_features_list = list()
    no_modified_features_pk = 29
    for i in detected_malware_idx:
       print("i: ", i)
       if malware_app[i] in malware_apk_fail:
           continue
       
       x_dict = X[malware_app_indices[i]]
       x = model.dict_to_feature_vector(x_dict) 
       x = x.toarray()
       _,x_adv_dict,no_modified_features = pk_attack(x,no_modified_features_pk,model.clf.coef_,model.vec.feature_names_,model)
       no_modified_features_list.append(no_modified_features)
       #print("no_modified_features: ",no_modified_features)
       x_adv = model.dict_to_feature_vector(x_adv_dict) 
       y_adv = model.clf.predict(x_adv)   
       y_pred_pk_attack.append(y_adv[0])
        
    no_evasion = [val for val in y_pred_pk_attack if val == 0]
    advs_idx = [index for index,val in enumerate(y_pred_pk_attack) if val == 0]
    advs_no_modified_features = [val for index,val in enumerate(no_modified_features_list) if index in advs_idx]
    sum(advs_no_modified_features)/len(advs_idx)
    ER_pk_attack = (len(no_evasion)/len(y_pred_pk_attack))*100  
    print("ER_pk_attack: ",ER_pk_attack)
    
    y_pred_random_attack = list()
    no_modified_features_random = 200
    for i in detected_malware_idx:
        print("i: ", i)
        if malware_app[i] in malware_apk_fail:
            continue
        x_dict = X[malware_app_indices[i]]
        x = model.dict_to_feature_vector(x_dict) 
        x = x.toarray()
        _,x_adv_dict = random_attack(x,len(model.vec.feature_names_),no_modified_features_random,model.vec.feature_names_)
        x_adv = model.dict_to_feature_vector(x_adv_dict) 
        y_adv = model.clf.predict(x_adv)   
        y_pred_random_attack.append(y_adv[0])
        
    no_evasion = [val for val in y_pred_random_attack if val == 0]
    ER_random_attack = (len(no_evasion)/len(y_pred_random_attack))*100  
    print("ER_random_attack: ",ER_random_attack)
    
    return ER_pk_attack,no_modified_features_pk,ER_random_attack,no_modified_features_random
    


def drebin():
    path = os.path.join(config['features'] , 'sub_dataset/', 'accessible_malware_index.p')
    with open(path,'rb') as f:
        malware_app = pickle.load(f) 
    
    X_filename = os.path.join(config['features'] , 'sub_dataset/', 'sub_dataset-X.json')   
    with open(X_filename, 'rt') as f:
        X = json.load(f)
   
    malware_app_indices = [item for item in malware_app.values()]
    malware_app = [item for item in malware_app.keys()]
    
    model = models.SVM("Drebin", False, config['X_dataset_inaccessible'], config['Y_dataset_inaccessible'],
                                  config['meta_inaccessible'],num_features = None,append = None)
    
    if os.path.exists(model.model_name):
        model = models.load_from_file(model.model_name)
    else:        
        model.generate()       
    
    y_pred = list()
    for app_index in malware_app_indices:
        malware_dict = X[app_index]
        x_malware = model.dict_to_feature_vector(malware_dict) 
        y_pred_app = model.clf.predict(x_malware)   
        y_pred.append(y_pred_app[0])
    DR = (sum(y_pred)/len(malware_app_indices))*100
    print("DR: ",DR)
    
    detected_malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]
    #malware_apps_name = [item for idx_item,item in enumerate(malware_app) if idx_item in detected_malware_idx]  
    path_fail = os.path.join(config['stored_components'],'malware_apk_fail.p')    
    with open(path_fail, 'rb') as f:
       malware_apk_fail = pickle.load(f)
    y_pred_pk_attack = list()
    no_modified_features_list = list()
    no_modified_features_pk = 8
    
    for i in detected_malware_idx:
       print("i: ", i)
       if malware_app[i] in malware_apk_fail:
           continue
       
       x_dict = X[malware_app_indices[i]]
       x = model.dict_to_feature_vector(x_dict) 
       x = x.toarray()
       _,x_adv_dict,no_modified_features = pk_attack(x,no_modified_features_pk,model.clf.coef_,model.vec.feature_names_,model)
       no_modified_features_list.append(no_modified_features)
       #print("no_modified_features: ",no_modified_features)
       x_adv = model.dict_to_feature_vector(x_adv_dict) 
       y_adv = model.clf.predict(x_adv)   
       y_pred_pk_attack.append(y_adv[0])
        
    no_evasion = [val for val in y_pred_pk_attack if val == 0]
    advs_idx = [index for index,val in enumerate(y_pred_pk_attack) if val == 0]
    advs_no_modified_features = [val for index,val in enumerate(no_modified_features_list) if index in advs_idx]
    sum(advs_no_modified_features)/len(advs_idx)
    ER_pk_attack = (len(no_evasion)/len(y_pred_pk_attack))*100  
    print("ER_pk_attack: ",ER_pk_attack)   
    
    
    y_pred_random_attack = list()
    no_modified_features_random = 200
    for i in detected_malware_idx:
        print("i: ", i)
        if malware_app[i] in malware_apk_fail:
            continue
        x_dict = X[malware_app_indices[i]]
        x = model.dict_to_feature_vector(x_dict) 
        x = x.toarray()
        _,x_adv_dict = random_attack(x,len(model.vec.feature_names_),no_modified_features_random,model.vec.feature_names_)
        x_adv = model.dict_to_feature_vector(x_adv_dict) 
        y_adv = model.clf.predict(x_adv)   
        y_pred_random_attack.append(y_adv[0])
        
    no_evasion = [val for val in y_pred_random_attack if val == 0]
    ER_random_attack = (len(no_evasion)/len(y_pred_random_attack))*100  
    print("ER_random_attack: ",ER_random_attack)
    
    return ER_pk_attack,no_modified_features_pk,ER_random_attack,no_modified_features_random

        