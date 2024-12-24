# -*- coding: utf-8 -*-
"""
Baseline evasion attacks
"""

import random
import numpy as np
import os
import pickle
from settings import config

#import attacks.models as models
import black_box_attack.models as models


import json
from scipy.sparse import csr_matrix


def loss_function(x_manipulated,model,malware_detector):
    '''
    if malware_detector == 'AdversarialDeepEnsembleMax':
        #y_scores_malware = model.test_new(x_malware,[1],'proba')[0,0]
        #The probability of becoming benign sample
        y_scores_adv_malware = model.test_new(x_manipulated,[1],'proba')[0,0] 
        #loss = y_scores_malware-y_scores_adv_malware
        loss = y_scores_adv_malware
        if y_scores_adv_malware >0.5:
            y_pred_adv = 0
        else:
            y_pred_adv = 1
        
    else:      
    '''
    if malware_detector=="Drebin":
        loss = model.clf.decision_function(x_manipulated)[0]         
        y_pred_adv = model.clf.predict(x_manipulated)[0]
    elif malware_detector=="SecSVM":
        loss = model.clf.decision_function(csr_matrix(x_manipulated))[0]         
        y_pred_adv = model.clf.predict(csr_matrix(x_manipulated))[0]
    elif malware_detector=="drebin_dnn":
        loss = model.clf.predict_proba(x_manipulated)[0] 
        loss = loss[0]
        #print("----------------loss",loss)
        y_pred_adv = model.clf.predict(x_manipulated)[0] 
        #print("----------------y_pred_adv",y_pred_adv)
    elif malware_detector == "AdversarialDeepEnsembleMax":
        y_pred_adv = model.test_new(x_manipulated,[1],'label')[0]  
        loss = model.test_new(x_manipulated,[1],'proba')[0,0] 
    return loss, y_pred_adv

def create_adversarial_example_sparse_RS_for_drebin_secsvm(x_malware, model, q = 10000, k = 100, alpha_init=1.6, model_name_val="Drebin"):
    '''
    Parameters:
        q: number of queries
        k: number of perturbation (sparsity)
        alpha: piecewise constant schedule
    '''
    #print("len(x_malware):", len(x_malware))
    #print("x_malware.shape:", x_malware.shape)
    
    U = [idx for idx,val in enumerate(x_malware) if val == 0]#sampling_distribution   
    M = U#random.sample(U,k)
    loss_best, y_pred_adv = loss_function(x_malware.reshape(1,-1),model,model_name_val)   
    print("loss_best=%f, y_pred_adv=%d"%(loss_best, y_pred_adv))
    best_perturbation = []
    i = 0
    #Queries in the paper N = {0; 50; 200; 500; 1000; 2000; 4000; 6000; 8000} in Sparse-RS paper
    #beta = {2, 4, 5, 6, 8, 10, 12, 15, 20} in Sparse-RS paper
    while y_pred_adv != 0 and i < q:
        if i < 5:
            beta = 2
        elif i<20:
            beta = 4
        elif i<50:
            beta = 5
        elif i<100:
            beta=6
        elif i<200:
            beta=8
        elif i<400:
            beta=10
        elif i<600:
            beta=12
        elif i<800:
            beta=15
        elif i>=800:
            beta=20  
        
        A_cardi = round((alpha_init / beta) * k)
        A = random.sample(M,(A_cardi))
        
        #U_temp = [x for x in U if x not in M]        
        U1 = set(U)
        A1 = set(A)
        U_temp = list(U1.difference(A1))
        #U_temp = [x for x in U if x not in A]
        
        B = random.sample(U_temp,A_cardi)
        
        M1 = set(M)
        M_new = list(M1.difference(A1)) + B
        #M_new = [x for x in M if x not in A] + B
        
        #unique elements: M_new_temp = (list(set(M_new)))
        x_adv_malware = np.copy(x_malware)
        #x_adv_malware[M] = 1
        x_adv_malware[A] = 1       
        loss, y_pred_adv = loss_function(x_adv_malware.reshape(1,-1),model,model_name_val)
        print("q=%d    loss=%f    y_pred_adv=%d"%(q,loss, y_pred_adv))
        if loss < loss_best:
            print("loss:",loss)
            loss_best = loss
            best_perturbation = A
            #x_malware = x_adv_malware
            #M_new = [val for val in M_new if val not in B]
            #U = [val for val in U if val not in B]             
            M = M_new
        i += 1   
    x_adv_malware =  np.copy(x_malware) 
    x_adv_malware[best_perturbation] = 1
    return x_malware,x_adv_malware.reshape(1,-1),i

def create_adversarial_example_sparse_RS(x_malware, model, q = 100, k = 100, alpha_init=1.6, model_name_val="Drebin"):
    '''
    Parameters:
        q: number of queries
        k: number of perturbation (sparsity)
        alpha: piecewise constant schedule
    '''
    #print("len(x_malware):", len(x_malware))
    #print("x_malware.shape:", x_malware.shape)
    
    U = [idx for idx,val in enumerate(x_malware) if val == 0]#sampling_distribution   
    M = U#random.sample(U,k)
    loss_best, y_pred_adv = loss_function(x_malware.reshape(1,-1),model,model_name_val)   
    print("loss_best=%f, y_pred_adv=%d"%(loss_best, y_pred_adv))
    best_perturbation = []
    i = 0
    #Queries in the paper N = {0; 50; 200; 500; 1000; 2000; 4000; 6000; 8000} in Sparse-RS paper
    #beta = {2, 4, 5, 6, 8, 10, 12, 15, 20} in Sparse-RS paper
    
    x_adv_malware_temp = list()
    stop_until_miss_classification = False
    #while y_pred_adv != 0 and i < q:
    while (y_pred_adv != 0 or stop_until_miss_classification == True) and i < q:
    #while i < q:
        if i < 5:
            beta = 2
        elif i<10:
            beta = 4
        elif i<15:
            beta = 5
        elif i<20:
            beta=6
        elif i<25:
            beta=8
        elif i<30:
            beta=10
        elif i<35:
            beta=12
        elif i<40:
            beta=15
        elif i>=45:
            beta=20  
        
        A_cardi = round((alpha_init / beta) * k)
        A = random.sample(M,(A_cardi))
        
        #U_temp = [x for x in U if x not in M]        
        U1 = set(U)
        A1 = set(A)
        U_temp = list(U1.difference(A1))
        #U_temp = [x for x in U if x not in A]
        
        B = random.sample(U_temp,A_cardi)
        
        M1 = set(M)
        M_new = list(M1.difference(A1)) + B
        #M_new = [x for x in M if x not in A] + B
        
        #unique elements: M_new_temp = (list(set(M_new)))
        x_adv_malware = np.copy(x_malware)
        #x_adv_malware[M] = 1
        x_adv_malware[A] = 1       
        loss, y_pred_adv = loss_function(x_adv_malware.reshape(1,-1),model,model_name_val)
        
        
        if y_pred_adv == 0:            
            stop_until_miss_classification = True
        elif stop_until_miss_classification == True:            
            break
         
        
        if model_name_val == "AdversarialDeepEnsembleMax":
            cmp = loss >= loss_best or y_pred_adv == 0
        else:
            loss < loss_best
        if cmp:            
            loss_best = loss
            best_perturbation = A
            #x_malware = x_adv_malware
            #M_new = [val for val in M_new if val not in B]
            #U = [val for val in U if val not in B]             
            M = M_new
        i += 1  
        print("q=%d    loss=%f    y_pred_adv=%d"%(i,loss, y_pred_adv))
    x_adv_malware =  np.copy(x_malware) 
    x_adv_malware[best_perturbation] = 1
    return x_malware,x_adv_malware.reshape(1,-1),i,sum(x_adv_malware)-sum(x_malware)

def random_attack_old(x,no_features,no_modifiable_features,features):     
    index_candidate_features = [idx for idx,val in enumerate(x[0]) if val == 0]
    features_rand = random.sample(index_candidate_features,no_modifiable_features)
    x_dict = dict()
    for f in range(0,len(features)):
        if f in features_rand:
            x[0][f] = 1 
        if x[0][f] == 1:
            x_dict[features[f]] = 1
    return x,x_dict


def random_attack(x,no_modifiable_features,model):     
    index_candidate_features = [idx for idx,val in enumerate(x[0]) if val == 0]    
    x_adv = np.copy(x)
    cnt = 0  
    for f in range(0,no_modifiable_features):
        if model.malware_detector == 'Drebin':
            y_adv = model.clf.predict(x_adv)[0]
        elif model.malware_detector == 'SecSVM':
            y_adv = model.clf.predict(csr_matrix(x_adv))[0]
        elif model.malware_detector == "AdversarialDeepEnsembleMax":
            y_adv = model.test_new(x_adv,[1],'label')[0]  
        if y_adv == 0:
            break
        features_rand = random.sample(index_candidate_features,1)[0]      
        x_adv[0][features_rand] = 1
        index_candidate_features.remove(features_rand)
        cnt += 1       
    return x,x_adv,cnt

def pk_feature_attack(x,no_modifiable_features,model):
    weights = model.clf.coef_
    abs_weights=np.absolute(weights)
    #sort_abs_weight=-np.sort(-abs_weights)
    sort_index=np.argsort(-abs_weights)  
    cnt = 0   
    x_adv = np.copy(x)
    for x_k in sort_index[0]:
        if model.malware_detector != 'SecSVM':
            y_adv = model.clf.predict(x_adv)[0]
        else:
            y_adv = model.clf.predict(csr_matrix(x_adv))[0]
        if y_adv == 0:
            break
        if cnt != no_modifiable_features and x[0][x_k] == 0 and weights[0][x_k]<0:
            x_adv[0][x_k] = 1 
            cnt += 1  
    return x,x_adv,cnt

def pk_attack(x,no_modifiable_features,weights,features):
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
    ACC = (sum(y_pred)/len(malware_app_indices))*100
    print("DR: ",ACC)
    
    detected_malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]
    #malware_apps_name = [item for idx_item,item in enumerate(malware_app) if idx_item in detected_malware_idx]  
    path_fail = os.path.join(config['stored_components'],'malware_apk_fail.p')    
    with open(path_fail, 'rb') as f:
       malware_apk_fail = pickle.load(f)
    y_pred_pk_attack = list()
    no_modified_features_list = list()
    no_modified_features_pk = 100   
    for i in detected_malware_idx:
       print("i: ", i)
       if malware_app[i] in malware_apk_fail:
           continue
       
       x_dict = X[malware_app_indices[i]]
       x = model.dict_to_feature_vector(x_dict) 
       x = x.toarray()
       _,x_adv,no_modified_features = pk_feature_attack(x,no_modified_features_pk,model.clf.coef_,model.vec.feature_names_,model)       
       no_modified_features_list.append(no_modified_features)      
       y_adv = model.clf.predict(csr_matrix(x_adv))   
       y_pred_pk_attack.append(y_adv[0])
        
    no_evasion = [val for val in y_pred_pk_attack if val == 0]
    advs_idx = [index for index,val in enumerate(y_pred_pk_attack) if val == 0]
    advs_no_modified_features = [val for index,val in enumerate(no_modified_features_list) if index in advs_idx]
    sum(advs_no_modified_features)/len(advs_idx)
    ER_pk_attack = (len(no_evasion)/len(y_pred_pk_attack))*100  
    print("ER_pk_attack: ",ER_pk_attack)
    print("No. added features pk_attack: ",sum(no_modified_features_list)/len(y_pred_pk_attack))
    
    return
    
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
    
#secsvm()

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
    ACC = (sum(y_pred)/len(malware_app_indices))*100
    print("ACC: ",ACC)
    
    detected_malware_idx = [idx_y for idx_y,y in enumerate(y_pred) if y == 1]
    #malware_apps_name = [item for idx_item,item in enumerate(malware_app) if idx_item in detected_malware_idx]  
    path_fail = os.path.join(config['stored_components'],'malware_apk_fail.p')    
    with open(path_fail, 'rb') as f:
       malware_apk_fail = pickle.load(f)
    y_pred_pk_attack = list()
    no_modified_features_list = list()
    no_modified_features_pk = 100 
    
    '''
    for i in detected_malware_idx:
       print("i: ", i)
       if malware_app[i] in malware_apk_fail:
           continue
       
       x_dict = X[malware_app_indices[i]]
       x = model.dict_to_feature_vector(x_dict) 
       x = x.toarray()
       _,x_adv,no_modified_features = pk_feature_attack(x,no_modified_features_pk,model.clf.coef_,model.vec.feature_names_,model)     
       no_modified_features_list.append(no_modified_features)
       y_adv = model.clf.predict(x_adv)   
       y_pred_pk_attack.append(y_adv[0])
        
    no_evasion = [val for val in y_pred_pk_attack if val == 0]   
   
    ER_pk_attack = (len(no_evasion)/len(y_pred_pk_attack))*100  
    print("ER_pk_attack: ",ER_pk_attack)
    print("No. added features pk_attack: ",sum(no_modified_features_list)/len(y_pred_pk_attack))
    
    return
    '''
    
    y_pred_random_attack = list()
    no_modified_features_random = 100
    for i in detected_malware_idx:
        print("i: ", i)
        if malware_app[i] in malware_apk_fail:
            continue
        x_dict = X[malware_app_indices[i]]
        x = model.dict_to_feature_vector(x_dict) 
        x = x.toarray()        
        #_,x_adv_dict = random_attack(x,len(model.vec.feature_names_),no_modified_features_random,model.vec.feature_names_)
        #x_adv = model.dict_to_feature_vector(x_adv_dict) 
        _,x_adv,no_modified_features = random_attack(x,no_modified_features_random,model)
        y_adv = model.clf.predict(x_adv)   
        y_pred_random_attack.append(y_adv[0])
        
    no_evasion = [val for val in y_pred_random_attack if val == 0]
    ER_random_attack = (len(no_evasion)/len(y_pred_random_attack))*100  
    print("ER_random_attack: ",ER_random_attack)
    
    #return ER_pk_attack,no_modified_features_pk,ER_random_attack,no_modified_features_random

#drebin()

def random_attack_dnn(x,no_modifiable_features):     
    index_candidate_features = [idx for idx,val in enumerate(x) if val == 0]    
    features_rand = random.sample(index_candidate_features,no_modifiable_features)    
    for f in range(0,10000):
        if f in features_rand:
            x[f] = 1   
    x = np.array(x)
    x = x.reshape(1,10000)
    return x

def ADE_MA(): 
    from defender import AdversarialDeepEnsembleMax     
    model_AdversarialDeepEnsembleMax = AdversarialDeepEnsembleMax()
    from tools import utils as utils_dnn    
    pris_data_path = "Projects/end-to-end_black-box_evasion_attack/data/drebin/attack/pristine_feature.data"
    if os.path.exists(pris_data_path):
        pris_feature_vectors = utils_dnn.readdata_np(pris_data_path)
    else:
        print("not exists")
    
    
    y_pred_random_attack = list()
    no_modified_features_random = 50
    i = 0
    for x in pris_feature_vectors:        
        x_adv = random_attack_dnn(x,no_modified_features_random)        
        y_adv = model_AdversarialDeepEnsembleMax.test_new(x_adv,[1],'label')[0]     
        y_pred_random_attack.append(y_adv)
        i += 1
        #print("y_malware=%d  - y_adv=%d - i=%d"%(y_malware,y_adv,i))  
        print("y_adv=%d - i=%d"%(y_adv,i))  
        
    no_evasion = [val for val in y_pred_random_attack if val == 0]
    ER_random_attack = (len(no_evasion)/len(y_pred_random_attack))*100  
    print("ER_random_attack: ",ER_random_attack)

        