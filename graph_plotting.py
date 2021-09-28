# -*- coding: utf-8 -*-
"""
Plotting graphs that are presented in [1].

[1] "EvadeDroid: A Practical Evasion Attack on Machine Learning for Black-box Android Malware Detection", 
EuroS&P 2022,  Submitted on Sept. 23, 2021. 
"""


import matplotlib.pyplot as plt 
import os
import pickle
from settings import config
from attacks import reference_attacks as baseline
import numpy as np
import math
import matplotlib.font_manager as font_manager
font = font_manager.FontProperties(family='Times New Roman',
                               weight='bold',
                               style='normal', size=16)

#for color intensity
from sklearn.preprocessing import MinMaxScaler

def customize_colors_intensity(data,min_val,max_val,chart_type):
    #https://adityarajgor.medium.com/how-to-change-color-density-of-matplotlib-barplot-bars-to-their-corresponding-values-74e81ad3a987
    data = np.append(data,min_val)
    data = np.append(data,max_val)
    scaler=MinMaxScaler()
    alphas = scaler.fit_transform(np.flip(data.reshape(-1,1)))
    
    alphas = np.delete(alphas,0)
    alphas = np.delete(alphas,0)
    alphas = np.flip(alphas)
    
    data = np.flip(data)
    data = np.delete(data,0)
    data = np.delete(data,0)
    data = np.flip(data)   
    
    
    rgba_colors = np.zeros((len(data),4))
    if chart_type == "evasion_rate":
        rgba_colors[:,0]=0.05078125  #value of red intensity divided by 256
        rgba_colors[:,1]=0.625  #value of green intensity divided by 256
        rgba_colors[:,2]=0.9609375  #value of blue intensity divided by 256
    elif chart_type == "avg_features":
         rgba_colors[:,0]=0.89453125  #value of red intensity divided by 256
         rgba_colors[:,1]=0.3359375  #value of green intensity divided by 256
         rgba_colors[:,2]=0.67578125  #value of blue intensity divided by 256
    elif chart_type == "avg_queries":
         rgba_colors[:,0]=0.3359375  #value of red intensity divided by 256
         rgba_colors[:,1]=0.89453125  #value of green intensity divided by 256
         rgba_colors[:,2]=0.70703125  #value of blue intensity divided by 256
    rgba_colors[:,-1]=alphas.reshape(1,len(data)).flatten()
    return rgba_colors
    
def plot_er_drebin_over_diff_evasion_cost_query():
    plt.figure(figsize=(10,10))
    number_of_query = 20 #I changed it in the middle of DREBIN-base_size = 0.1 - hard_label = False
    base_size = 0.1    
    hard_label = False    
    path_base = os.path.join(config['results_dir'],'EvadeDroid/Drebin')  
    for s in range(1,6):   
        
        if hard_label == True:
           hardlabel = 1
        else:
           hardlabel = 0            
        increase_in_size = base_size * s
        name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
        path = os.path.join(path_base,name)   
        er_per_query = dict()
        #base_path = "C:/GitLab/end-to-end_black-box_evasion_attack/data/stored-components/attack-results/EvadeDroid/Drebin/result-noquery_20-size_0.100000-hardlabel_0"
        apk_name = os.listdir(path)
        cnt_corrupt = 0
        for app in apk_name:
            apk_info_path = os.path.join(path,app)
            with open(apk_info_path , 'rb') as f:
                apk = pickle.load(f)
            if apk.intact_due_to_soot_error == 1:
                cnt_corrupt += 1
            if apk.adv_malware_label == 0:
                if apk.number_of_queries in er_per_query.keys():
                    er_per_query[apk.number_of_queries] += 1
                else:
                    er_per_query[apk.number_of_queries] = 1        
        X = list()
        Y = list()
        total = len(apk_name) - cnt_corrupt
        for i in range(1,21):       
            if i not in er_per_query.keys():
                er_per_query[i] = 0
            X.append(i)
            SUM = 0
            for j in range(1,i + 1):
                SUM = SUM + er_per_query[j]
            #plt.ylim([10, 80])
            plt.xlim([0, 21])
            Y.append((SUM/total)*100)    
        ec = str(increase_in_size*100)
        ec_caption ="Evasion Cost (%)"
        plt.rc('legend',fontsize=15)
        plt.rc('xtick', labelsize=15) 
        plt.rc('ytick', labelsize=15)
        plt.plot(X, Y, label = "%s = %s"%(ec_caption,ec[0:2]),lw=2, alpha=.8) 
        
    # Labeling the X-axis 
    plt.xlabel('Query Budget',fontsize=18) 
    
    # Labeling the Y-axis 
    plt.ylabel('Evasion Rate (%)',fontsize=18) 
    
    
    # Give a title to the graph
    #plt.title('Two plots on the same graph') 
      
    # Show a legend on the plot 
    plt.legend() 
    
    X_axis = [1,5,10,15,20]
    plt.xticks(X_axis)
    plt.grid()
    plt.savefig(os.path.join(config['result_graphs'], "Drebin_er_diff_ec.jpg"), format='jpg', dpi=800)  
    plt.show()
            

#plot_er_drebin_over_diff_evasion_cost_query()
    
def plot_er_drebin_soft_hard_label():  
    plt.figure(figsize=(20,5))
    path_base = os.path.join(config['results_dir'],'EvadeDroid/Drebin')  
    hardlabel = 1
    number_of_query = 20 #I changed it in the middle of DREBIN-base_size = 0.1 - hard_label = False
    base_size = 0.1            
    increase_in_size = base_size * 5
    
    name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
    path = os.path.join(path_base,name)       
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    total_no_query = 0    
    total_rel_inc_size = 0
    no_detected = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            total_no_query += apk.number_of_queries
            total_rel_inc_size += apk.percentage_increasing_size
            no_detected += 1
    
    avg_query_hard = total_no_query/no_detected
    avg_rel_inc_size_hard = total_rel_inc_size/no_detected
    avg_er_hard = no_detected/(len(apk_name) - cnt_corrupt)
    
    
    hardlabel = 0
    name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
    path = os.path.join(path_base,name)       
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    total_no_query = 0    
    total_rel_inc_size = 0
    no_detected = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            total_no_query += apk.number_of_queries
            total_rel_inc_size += apk.percentage_increasing_size
            no_detected += 1
    
    avg_query_soft = total_no_query/no_detected
    avg_rel_inc_size_soft = total_rel_inc_size/no_detected
    avg_er_soft = no_detected/(len(apk_name) - cnt_corrupt)
    
    
    #plt.figure(figsize=(4,5))
    rows, cols = 1, 3    
    
    plt.subplot(rows, cols, 1)    
    avg_er = [avg_er_soft*100,avg_er_hard*100]
    langs = ['Soft Label', 'Hard Label']      
    plt.grid(axis='y',zorder=0)   
    arr_avg_er = np.array(avg_er)
    plt.bar(langs, avg_er, width = 0.3,zorder=3, edgecolor = 'black',color='white')
    rgba_colors = customize_colors_intensity(arr_avg_er,-20,max(arr_avg_er),"evasion_rate")
    graph = plt.bar(langs, avg_er, width = 0.3,zorder=3, edgecolor = 'black',color=rgba_colors)
    i = 0
    for p in graph:
        width = p.get_width()
        height = p.get_height()
        x, y = p.get_xy()
        plt.text(x+width/2,
                 y+height*1.01,
                 str(round(avg_er[i],2)),
                 ha='center',
                 weight='normal')
        i += 1   
    
    plt.margins(0.2, 0.2)
    plt.xticks(fontsize=15,fontname="Times New Roman")
    plt.yticks(fontsize=15,fontname="Times New Roman")
    plt.margins(0.2, 0.2)   
    plt.ylabel('ER (%)',fontsize=16,fontname="Times New Roman")     
    
    plt.subplot(rows, cols, 2)
    
    #plt.rc('legend',fontsize=15)
    #plt.rc('xtick', labelsize=15) 
    #plt.rc('ytick', labelsize=15)
    
    
    avg_query = [avg_query_soft,avg_query_hard]    
    plt.grid(axis='y',zorder=0)
    plt.bar(langs, avg_query, width = 0.3,zorder=3)
    
    
    arr_avg_query = np.array(avg_query)
    plt.bar(langs, avg_query, width = 0.3,zorder=3, edgecolor = 'black',color='white')
    rgba_colors = customize_colors_intensity(arr_avg_query,-20,max(arr_avg_query),"avg_queries")
    graph = plt.bar(langs, avg_query, width = 0.3,zorder=3, edgecolor = 'black',color=rgba_colors)
    i = 0
    for p in graph:
        width = p.get_width()
        height = p.get_height()
        x, y = p.get_xy()
        plt.text(x+width/2,
                 y+height*1.01,
                 str(round(avg_query[i],2)),
                 ha='center',
                 weight='normal')
        i += 1 
        
    plt.margins(0.2, 0.2)
    plt.xticks(fontsize=15,fontname="Times New Roman")
    plt.yticks(fontsize=15,fontname="Times New Roman")
    plt.margins(0.2, 0.2)   
    plt.ylabel('Avg. Number of Queries',fontsize=16,fontname="Times New Roman")     
   
    
    plt.subplot(rows, cols, 3)
    
    avg_rel_inc_size = [avg_rel_inc_size_soft*100,avg_rel_inc_size_hard*100]
    plt.grid(axis='y',zorder=0)
    plt.bar(langs, avg_rel_inc_size, width = 0.3,zorder=3)
    
    arr_avg_rel_inc_size = np.array(avg_rel_inc_size)
    plt.bar(langs, avg_rel_inc_size, width = 0.3,zorder=3, edgecolor = 'black',color='white')
    rgba_colors = customize_colors_intensity(arr_avg_rel_inc_size,-20,max(arr_avg_rel_inc_size),"avg_features")
    graph = plt.bar(langs, avg_rel_inc_size, width = 0.3,zorder=3, edgecolor = 'black',color=rgba_colors)
    i = 0
    for p in graph:
        width = p.get_width()
        height = p.get_height()
        x, y = p.get_xy()
        plt.text(x+width/2,
                 y+height*1.01,
                 str(round(avg_rel_inc_size[i],2)),
                 ha='center',
                 weight='normal')
        i += 1 
    
    plt.margins(0.2, 0.2)
    plt.margins(0.2, 0.2)
    plt.xticks(fontsize=15,fontname="Times New Roman")
    plt.yticks(fontsize=15,fontname="Times New Roman")
    plt.margins(0.2, 0.2)   
    plt.ylabel('Avg. Relative Increase in Size (%)',fontsize=16,fontname="Times New Roman")     
        
    plt.savefig(os.path.join(config['result_graphs'],"drebin_soft_hard_label.jpg"), format='jpg', dpi=800)        
    plt.show()  
    
def plot_er_drebin_secsvm_over_diff_queries():
    plt.figure(figsize=(10,10))
    number_of_query = 20 #I changed it in the middle of DREBIN-base_size = 0.1 - hard_label = False
    base_size = 0.1       
    path_base = os.path.join(config['results_dir'],'EvadeDroid/Drebin')  
    hardlabel = 0          
    increase_in_size = base_size * 5
    name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
    path = os.path.join(path_base,name)   
    er_per_query = dict()
    #base_path = "C:/GitLab/end-to-end_black-box_evasion_attack/data/stored-components/attack-results/EvadeDroid/Drebin/result-noquery_20-size_0.100000-hardlabel_0"
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            if apk.number_of_queries in er_per_query.keys():
                er_per_query[apk.number_of_queries] += 1
            else:
                er_per_query[apk.number_of_queries] = 1        
    X = list()
    Y = list()
    total = len(apk_name) - cnt_corrupt
    for i in range(1,21):       
        if i not in er_per_query.keys():
            er_per_query[i] = 0
        X.append(i)
        SUM = 0
        for j in range(1,i + 1):
            SUM = SUM + er_per_query[j]
        #plt.ylim([10, 80])
        plt.xlim([0, 21])
        Y.append((SUM/total)*100)    
    ec = str(increase_in_size*100)
    
    plt.rc('legend',fontsize=15)
    plt.rc('xtick', labelsize=15) 
    plt.rc('ytick', labelsize=15)
    plt.plot(X, Y, label = "DREBIN",lw=2, alpha=.8)     
    
    path_base = os.path.join(config['results_dir'],'EvadeDroid/SecSVM')     
    name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
    path = os.path.join(path_base,name)   
    er_per_query = dict()
    #base_path = "C:/GitLab/end-to-end_black-box_evasion_attack/data/stored-components/attack-results/EvadeDroid/Drebin/result-noquery_20-size_0.100000-hardlabel_0"
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            if apk.number_of_queries in er_per_query.keys():
                er_per_query[apk.number_of_queries] += 1
            else:
                er_per_query[apk.number_of_queries] = 1        
    X = list()
    Y = list()
    total = len(apk_name) - cnt_corrupt
    for i in range(1,21):       
        if i not in er_per_query.keys():
            er_per_query[i] = 0
        X.append(i)
        SUM = 0
        for j in range(1,i + 1):
            SUM = SUM + er_per_query[j]
        #plt.ylim([10, 80])
        plt.xlim([0, 21])
        Y.append((SUM/total)*100)    
    ec = str(increase_in_size*100)   
    
    plt.rc('legend',fontsize=15)
    plt.rc('xtick', labelsize=15) 
    plt.rc('ytick', labelsize=15)
    plt.plot(X, Y, label = "Sec-SVM",lw=2, alpha=.8) 
    
    plt.legend(prop=font) 
        
        
    # Labeling the X-axis 
    plt.xlabel('Query Budget',fontsize=16,fontname="Times New Roman") 
    
    # Labeling the Y-axis 
    plt.ylabel('Evasion Rate (%)',fontsize=16,fontname="Times New Roman")     
    
    X_axis = [1,5,10,15,20]
    #plt.xticks(X_axis)
    plt.xticks(X_axis,fontsize=15,fontname="Times New Roman")
    plt.yticks(fontsize=15,fontname="Times New Roman")
    plt.grid()
    plt.savefig(os.path.join(config['result_graphs'],"drebin_secsvm_over_diff_queries.jpg"), format='jpg', dpi=800)   
    plt.show()

def plot_er_drebin_over_diff_evasion_cost():
    plt.figure(figsize=(20,6))
    number_of_query = 20 #I changed it in the middle of DREBIN-base_size = 0.1 - hard_label = False
    base_size = 0.1    
    hard_label = False    
    path_base = os.path.join(config['results_dir'],'EvadeDroid/Drebin')  
    avg_er = list()
    avg_feature = list()
    for s in range(1,6):   
        
        if hard_label == True:
           hardlabel = 1
        else:
           hardlabel = 0            
        increase_in_size = base_size * s
        name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
        path = os.path.join(path_base,name)   
       
        apk_name = os.listdir(path)       
        
        cnt_corrupt = 0
        total_no_query = 0    
        total_rel_inc_size = 0
        no_detected = 0
        total_no_feature = 0
        cnt_no_fature_check = 0
        for app in apk_name:
            apk_info_path = os.path.join(path,app)
            with open(apk_info_path , 'rb') as f:
                apk = pickle.load(f)
            if apk.intact_due_to_soot_error == 1:
                cnt_corrupt += 1
            if apk.adv_malware_label == 0:
                total_no_query += apk.number_of_queries
                total_rel_inc_size += apk.percentage_increasing_size
                '''
                if apk.number_of_features_adv_malware - apk.number_of_features_malware > 0:
                    total_no_feature += apk.number_of_features_adv_malware - apk.number_of_features_malware
                    cnt_no_fature_check += 1
                '''
                total_no_feature += apk.number_of_features_adv_malware - apk.number_of_features_malware
                no_detected += 1
        
        #avg_query_soft = total_no_query/no_detected
        #avg_rel_inc_size_soft = total_rel_inc_size/no_detected
        avg_er_soft = no_detected/(len(apk_name) - cnt_corrupt)
        avg_er.append(avg_er_soft*100)
        avg_no_feature = total_no_feature/no_detected
        avg_feature.append(avg_no_feature)
        
        
    langs = ['10', '20','30','40','50']    
    rows, cols = 1, 2    
    plt.subplot(rows, cols, 1)    
    plt.grid(axis='y',zorder=0)
    graph = plt.bar(langs, avg_er, width = 0.4,zorder=3,edgecolor = 'black')    
    
    arr_avg_er = np.array(avg_er)
    plt.bar(langs, avg_er, width = 0.4,zorder=3, edgecolor = 'black',color='white')
    rgba_colors = customize_colors_intensity(arr_avg_er,-20,max(arr_avg_er),"evasion_rate")
    graph = plt.bar(langs, avg_er, width = 0.4,zorder=3, edgecolor = 'black',color=rgba_colors)
    
    i = 0
    for p in graph:
        width = p.get_width()
        height = p.get_height()
        x, y = p.get_xy()
        plt.text(x+width/2,
                 y+height*1.01,
                 str(round(avg_er[i],2)),
                 ha='center',
                 weight='normal')
        i += 1
    plt.xticks(fontsize=15,fontname="Times New Roman")
    plt.yticks(fontsize=15,fontname="Times New Roman")
    plt.margins(0.2, 0.2)   
    plt.ylabel('ER (%)',fontsize=16,fontname="Times New Roman")     
    plt.xlabel(r'$\alpha$ (%)',fontsize=16,fontname="Times New Roman")
    
    plt.subplot(rows, cols, 2)
    plt.grid(axis='y',zorder=0)
    arr_avg_features = np.array(avg_feature)
    plt.bar(langs, avg_feature, width = 0.4,zorder=3, edgecolor = 'black',color='white')
    rgba_colors = customize_colors_intensity(arr_avg_features,-20,max(arr_avg_features),"avg_features")
    graph = plt.bar(langs, avg_feature, width = 0.4,zorder=3, edgecolor = 'black',color=rgba_colors)
    i = 0
    for p in graph:
        width = p.get_width()
        height = p.get_height()
        x, y = p.get_xy()
        plt.text(x+width/2,
                 y+height*1.01,
                 str(round(avg_feature[i],2)),
                 ha='center',
                 weight='normal')
        i += 1
    plt.xticks(fontsize=15,fontname="Times New Roman")
    plt.yticks(fontsize=15,fontname="Times New Roman")
    plt.margins(0.2, 0.2)   
    plt.ylabel('Avg. Number of Added DREBIN Features (%)',fontsize=16,fontname="Times New Roman")     
    plt.xlabel(r'$\alpha$ (%)',fontsize=16,fontname="Times New Roman")    
    plt.savefig(os.path.join(config['result_graphs'],'drebin_over_diff_evasion_cost.jpg'), format='jpg', dpi=800)          
    plt.show()

plot_er_drebin_over_diff_evasion_cost()

def plot_compare_evadedroid_pk_random_attacks():  
    plt.figure(figsize=(20,12))
    path_base = os.path.join(config['results_dir'],'EvadeDroid/Drebin')  
    hardlabel = 0
    number_of_query = 20 #I changed it in the middle of DREBIN-base_size = 0.1 - hard_label = False
    base_size = 0.1            
    increase_in_size = base_size * 5
    
    name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
    path = os.path.join(path_base,name)       
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    total_no_query = 0    
   
    total_number_of_manipulated_features = 0
    no_detected = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            total_number_of_manipulated_features += apk.number_of_features_adv_malware - apk.number_of_features_malware
            total_no_query += apk.number_of_queries            
            no_detected += 1
    
    avg_total_number_of_manipulated_features_drebin = total_number_of_manipulated_features/no_detected    
    er_evadedroid_drebin = no_detected/(len(apk_name) - cnt_corrupt)
    
    path_base = os.path.join(config['results_dir'],'EvadeDroid/SecSVM')
    name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
    path = os.path.join(path_base,name)       
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    total_no_query = 0    
   
    total_number_of_manipulated_features = 0
    no_detected = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            total_number_of_manipulated_features += apk.number_of_features_adv_malware - apk.number_of_features_malware
            total_no_query += apk.number_of_queries            
            no_detected += 1
    avg_total_number_of_manipulated_features_secsvm = total_number_of_manipulated_features/no_detected    
    er_evadedroid_secsvm = no_detected/(len(apk_name) - cnt_corrupt)
    
    er_pk_drebin,no_modified_features_pk_drebin,er_random_drebin,no_modified_features_random_drebin = baseline.drebin()
    er_pk_secsvm,no_modified_features_pk_secsvm,er_random_secsvm,no_modified_features_random_secsvm = baseline.secsvm()
            
    rows, cols = 2, 2   
    plt.subplot(rows, cols, 1)    
    avg_er_drebin = [er_evadedroid_drebin*100,er_pk_drebin*100,er_random_drebin*100]    
    plt.grid(axis='y',zorder=0)
    langs = ['EvadeDroid', 'PK', 'Random']    
    arr_avg_er_drebin = np.array(avg_er_drebin)
    plt.bar(langs, avg_er_drebin, width = 0.3,zorder=3, edgecolor = 'black',color='white')
    rgba_colors = customize_colors_intensity(arr_avg_er_drebin,-20,max(arr_avg_er_drebin),"evasion_rate")
    graph = plt.bar(langs, avg_er_drebin, width = 0.3,zorder=3, edgecolor = 'black',color=rgba_colors)
    i = 0
    for p in graph:
        width = p.get_width()
        height = p.get_height()
        x, y = p.get_xy()
        plt.text(x+width/2,
                 y+height*1.01,
                 str(round(avg_er_drebin[i],2)),
                 ha='center',
                 weight='normal')
        i += 1       
    plt.margins(0.2, 0.2)
    plt.ylabel('ER (%)',fontsize=16,fontname="Times New Roman") 
    plt.xticks(fontsize=15,fontname="Times New Roman")
    plt.yticks(fontsize=15,fontname="Times New Roman")    
    
    plt.subplot(rows, cols, 2)    
    avg_er_secsvm = [er_evadedroid_secsvm*100,er_pk_secsvm*100,er_random_secsvm*100]
    langs = ['EvadeDroid', 'PK', 'Random']
    plt.grid(axis='y',zorder=0)    
    arr_er_secsvm = np.array(avg_er_secsvm)
    plt.bar(langs, avg_er_secsvm, width = 0.3,zorder=3, edgecolor = 'black',color='white')
    rgba_colors = customize_colors_intensity(arr_er_secsvm,-20,max(avg_er_secsvm),"evasion_rate")
    graph = plt.bar(langs, avg_er_secsvm, width = 0.3,zorder=3, edgecolor = 'black',color=rgba_colors)
    i = 0
    for p in graph:
        width = p.get_width()
        height = p.get_height()
        x, y = p.get_xy()
        plt.text(x+width/2,
                 y+height*1.01,
                 str(round(avg_er_secsvm[i],2)),
                 ha='center',
                 weight='normal')
        i += 1       
    plt.margins(0.2, 0.2)
    plt.ylabel('ER (%)',fontsize=16,fontname="Times New Roman") 
    plt.xticks(fontsize=15,fontname="Times New Roman")
    plt.yticks(fontsize=15,fontname="Times New Roman")            
    plt.subplot(rows, cols, 3)    
    avg_no_feature_drebin = [avg_total_number_of_manipulated_features_drebin,no_modified_features_pk_drebin,no_modified_features_random_drebin]
    plt.grid(axis='y',zorder=0)    
    
    arr_avg_no_feature_drebin = np.array(avg_no_feature_drebin)
    plt.bar(langs, arr_avg_no_feature_drebin, width = 0.3,zorder=3, edgecolor = 'black',color='white')
    rgba_colors = customize_colors_intensity(avg_no_feature_drebin,-20,max(avg_no_feature_drebin),"avg_features")
    graph = plt.bar(langs, avg_no_feature_drebin, width = 0.3,zorder=3, edgecolor = 'black',color=rgba_colors)
    i = 0
    for p in graph:
        width = p.get_width()
        height = p.get_height()
        x, y = p.get_xy()
        plt.text(x+width/2,
                 y+height*1.01,
                 str(round(avg_no_feature_drebin[i],2)),
                 ha='center',
                 weight='normal')
        i += 1   
    
    plt.margins(0.2, 0.2)
    plt.ylabel('Number of added DREBIN features',fontsize=16,fontname="Times New Roman") 
    plt.xlabel('(a) DREBIN',fontsize=16,fontname="Times New Roman") 
    plt.xticks(fontsize=15,fontname="Times New Roman")
    plt.yticks(fontsize=15,fontname="Times New Roman")
    
    plt.subplot(rows, cols, 4)    
    avg_no_feature_secsvm = [avg_total_number_of_manipulated_features_secsvm,no_modified_features_pk_secsvm,no_modified_features_random_secsvm]
    plt.grid(axis='y',zorder=0)
    plt.bar(langs, avg_no_feature_secsvm, width = 0.3,zorder=3)    
    arr_avg_no_feature_secsvm = np.array(avg_no_feature_secsvm)
    plt.bar(langs, arr_avg_no_feature_secsvm, width = 0.3,zorder=3, edgecolor = 'black',color='white')
    rgba_colors = customize_colors_intensity(avg_no_feature_secsvm,-20,max(avg_no_feature_drebin),"avg_features")
    graph = plt.bar(langs, avg_no_feature_secsvm, width = 0.3,zorder=3, edgecolor = 'black',color=rgba_colors)
    i = 0
    for p in graph:
        width = p.get_width()
        height = p.get_height()
        x, y = p.get_xy()
        plt.text(x+width/2,
                 y+height*1.01,
                 str(round(avg_no_feature_secsvm[i],2)),
                 ha='center',
                 weight='normal')
        i += 1   
    
    plt.margins(0.2, 0.2)
    plt.ylabel('Number of added DREBIN features',fontsize=16,fontname="Times New Roman") 
    plt.xlabel('(b) Sec-SVM',fontsize=16,fontname="Times New Roman") 
    plt.xticks(fontsize=15,fontname="Times New Roman")
    plt.yticks(fontsize=15,fontname="Times New Roman")
    plt.savefig(os.path.join(config['result_graphs'],"evadedroid_pk_random.jpg"),format='jpg', dpi=800)  
    plt.show()   

    
def plot_compare_evadedroid_against_diff_malware_detectors():  
    plt.figure(figsize=(15,10))
    path_base = os.path.join(config['results_dir'],'EvadeDroid/Drebin')  
    hardlabel = 0
    number_of_query = 20 #I changed it in the middle of DREBIN-base_size = 0.1 - hard_label = False
    base_size = 0.1            
    increase_in_size = base_size * 5
    
    name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
    path = os.path.join(path_base,name)       
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    total_no_query = 0     
    total_ec = 0
    no_detected = 0
    total_api_calls = 0
    total_no_transformations = 0
    total_no_features = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            total_ec += apk.percentage_increasing_size
            total_no_query += apk.number_of_queries 
            total_api_calls += apk.number_of_api_calls_adv_malware - apk.number_of_api_calls_malware
            no_detected += 1
            total_no_transformations += len(apk.transformations)
            total_no_features += apk.number_of_features_adv_malware - apk.number_of_features_malware
    
    avg_total_no_transformations_drebin = total_no_transformations/no_detected
    avg_total_no_features_drebin = total_no_features/no_detected
    avg_total_api_calls_drebin = total_api_calls/no_detected
    avg_total_ec_drebin = total_ec/no_detected
    avg_total_no_query_drebin = total_no_query/no_detected
    N = (len(apk_name) - cnt_corrupt)
    er_evadedroid_drebin = no_detected/N
    
    total_ec = 0
    total_no_query = 0
    total_api_calls = 0
    total_no_features = 0
    total_no_transformations = 0
    for app in apk_name:
        if app == "com.alsatiamedia.recipeshealthycasseroles.p":
            print(app)
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)       
        if apk.adv_malware_label == 0:
            total_ec += (apk.percentage_increasing_size - avg_total_ec_drebin)**2
            total_no_query += (apk.number_of_queries - avg_total_no_query_drebin)**2  
            total_api_calls += ((apk.number_of_api_calls_adv_malware - apk.number_of_api_calls_malware) - avg_total_api_calls_drebin)**2   
            total_no_features += ((apk.number_of_features_adv_malware - apk.number_of_features_malware) - avg_total_no_features_drebin)**2
            total_no_transformations += (len(apk.transformations)-avg_total_no_transformations_drebin)**2
            
    std_total_no_transformations_drebin = math.sqrt(total_no_transformations/(no_detected-1))
    std_total_no_features_drebin = math.sqrt(total_no_features/(no_detected-1))
    std_total_api_calls_drebin = math.sqrt(total_api_calls/(no_detected-1))
    std_total_ec_drebin = math.sqrt(total_ec/(no_detected))
    std_total_no_query_drebin = math.sqrt(total_no_query/(no_detected-1))
    
    path_base = os.path.join(config['results_dir'],'EvadeDroid/SecSVM')
    name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
    path = os.path.join(path_base,name)       
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    total_no_query = 0     
    total_ec = 0
    no_detected = 0
    total_api_calls = 0
    total_no_transformations = 0
    total_no_features = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            total_ec += apk.percentage_increasing_size
            total_no_query += apk.number_of_queries  
            total_api_calls += apk.number_of_api_calls_adv_malware - apk.number_of_api_calls_malware
            no_detected += 1
            total_no_transformations += len(apk.transformations)
            total_no_features += apk.number_of_features_adv_malware - apk.number_of_features_malware
            
    avg_total_no_features_secsvm = total_no_features/no_detected
    avg_total_no_transformations_secsvm = total_no_transformations/no_detected
    avg_total_api_calls_secsvm = total_api_calls/no_detected
    avg_total_ec_secsvm = total_ec/no_detected
    avg_total_no_query_secsvm = total_no_query/no_detected  
    N = (len(apk_name) - cnt_corrupt)     
    er_evadedroid_secsvm = no_detected/N
    
    total_ec = 0
    total_no_query = 0
    total_api_calls = 0  
    total_no_features = 0
    total_no_transformations = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)       
        if apk.adv_malware_label == 0:
            total_ec += (apk.percentage_increasing_size - avg_total_ec_secsvm)**2
            total_no_query += (apk.number_of_queries - avg_total_no_query_secsvm)**2   
            total_api_calls += ((apk.number_of_api_calls_adv_malware - apk.number_of_api_calls_malware) - avg_total_api_calls_secsvm)**2   
            total_no_features += ((apk.number_of_features_adv_malware - apk.number_of_features_malware) - avg_total_no_features_secsvm)**2
            total_no_transformations += (len(apk.transformations)-avg_total_no_transformations_secsvm)**2
            
    std_total_no_transformations_secsvm = math.sqrt(total_no_transformations/(no_detected-1))
    std_total_no_features_secsvm = math.sqrt(total_no_features/(no_detected-1))
    std_total_api_calls_secsvm = math.sqrt(total_api_calls/(no_detected-1))
    std_total_ec_secsvm = math.sqrt(total_ec/(no_detected-1))
    std_total_no_query_secsvm = math.sqrt(total_no_query/(no_detected))
        
    path_base = os.path.join(config['results_dir'],'EvadeDroid/MaMaDroid')
    name = "result-noquery_%d-size_%f-hardlabel_%d"%(number_of_query,increase_in_size,hardlabel)
    path = os.path.join(path_base,name)       
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    total_no_query = 0     
    total_ec = 0
    no_detected = 0
    total_api_calls = 0
    total_no_features = 0
    total_no_transformations = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            total_ec += apk.percentage_increasing_size
            total_no_query += apk.number_of_queries  
            total_api_calls += apk.number_of_api_calls_adv_malware - apk.number_of_api_calls_malware
            no_detected += 1
            total_no_features += apk.number_of_features_adv_malware - apk.number_of_features_malware
            total_no_transformations += len(apk.transformations)
    
    avg_total_no_features_mamadroid = total_no_features/no_detected
    avg_total_no_transformations_mamadroid = total_no_transformations/no_detected
    
    avg_total_api_calls_mamadroid = total_api_calls/no_detected
    avg_total_ec_mamadroid = total_ec/no_detected
    avg_total_no_query_mamadroid = total_no_query/no_detected     
    N = (len(apk_name) - cnt_corrupt)
    er_evadedroid_mamadroid = no_detected/N
    
    total_ec = 0
    total_no_query = 0
    total_api_calls = 0
    total_no_features = 0
    total_no_transformations = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)       
        if apk.adv_malware_label == 0:
            total_ec += (apk.percentage_increasing_size - avg_total_ec_mamadroid)**2
            total_no_query += (apk.number_of_queries - avg_total_no_query_mamadroid)**2   
            total_api_calls += ((apk.number_of_api_calls_adv_malware - apk.number_of_api_calls_malware) - avg_total_api_calls_mamadroid)**2   
            total_no_features += ((apk.number_of_features_adv_malware - apk.number_of_features_malware) - avg_total_no_features_mamadroid)**2
            total_no_transformations += (len(apk.transformations)-avg_total_no_transformations_mamadroid)**2
            
    std_total_no_transformations_mamadroid = math.sqrt(total_no_transformations/(no_detected-1))
    std_total_no_features_mamadroid = math.sqrt(total_no_features/(no_detected-1))
    std_total_api_calls_mamadroid = math.sqrt(total_api_calls/(no_detected-1))
    std_total_ec_mamadroid = math.sqrt(total_ec/(no_detected-1))
    std_total_no_query_mamadroid = math.sqrt(total_no_query/(no_detected))
   
    
    print("ER - DREBIN: %f     Sec-SVM: %f     MaMaDroid: %f"%(er_evadedroid_drebin,er_evadedroid_secsvm,er_evadedroid_mamadroid))
    print("Avg. No. Queries - DREBIN: %f + %f     Sec-SVM: %f + %f     MaMaDroid: %f + %f"%(avg_total_no_query_drebin,std_total_no_query_drebin,avg_total_no_query_secsvm,std_total_no_query_secsvm,avg_total_no_query_mamadroid,std_total_no_query_mamadroid))
    print("Avg. Relative Increase in Size - DREBIN: %f + %f     Sec-SVM: %f + %f    MaMaDroid: %f + %f"%(avg_total_ec_drebin*100,std_total_ec_drebin*100,avg_total_ec_secsvm*100,std_total_ec_secsvm*100,avg_total_ec_mamadroid*100,std_total_ec_mamadroid*100))
    print("Avg. No. of Added API calls - DREBIN: %f + %f     Sec-SVM: %f + %f    MaMaDroid: %f + %f"%(avg_total_api_calls_drebin,std_total_api_calls_drebin,avg_total_api_calls_secsvm,std_total_api_calls_secsvm,avg_total_api_calls_mamadroid,std_total_api_calls_mamadroid))
    print("Avg. No. of Modified Features - DREBIN: %f + %f     Sec-SVM: %f + %f    MaMaDroid: %f + %f"%(avg_total_no_features_drebin,std_total_no_features_drebin,avg_total_no_features_secsvm,std_total_no_features_secsvm,avg_total_no_features_mamadroid,std_total_no_features_mamadroid))
    print("Avg. No. of Transformations - DREBIN: %f + %f     Sec-SVM: %f + %f    MaMaDroid: %f + %f"%(avg_total_no_transformations_drebin,std_total_no_transformations_drebin,avg_total_no_transformations_secsvm,std_total_no_transformations_secsvm,avg_total_no_transformations_mamadroid,std_total_no_transformations_mamadroid))
        

def plot_compare_evadedroid_against_virustotal():  
    plt.figure(figsize=(15,10))
    path_base = os.path.join(config['results_dir'],'EvadeDroid/VirusTotal')  
    name = "result_Kaspersky"
    path = os.path.join(path_base,name)       
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    total_no_query = 0     
    total_ec = 0
    no_detected = 0
    total_malware = 100
    total_time = 0
    cnt_time = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            total_ec += apk.percentage_increasing_size
            total_no_query += apk.number_of_queries            
            no_detected += 1
            if apk.execution_time > 1:
                total_time += apk.execution_time
                cnt_time += 1    
    
    avg_total_no_query_kaspersky = total_no_query/no_detected       
    er_evadedroid_kaspersky = (no_detected/(len(apk_name) - cnt_corrupt))*100
    dr_evadedroid_kaspersky_before_attack = (len(apk_name)/total_malware)*100
    dr_evadedroid_kaspersky_after_attack = ((len(apk_name) - no_detected)/total_malware)*100
    avg_execution_time_kaspersky = total_time/cnt_time
    
    
    name = "result_ESETNOD32"
    path = os.path.join(path_base,name)       
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    total_no_query = 0     
    total_ec = 0
    no_detected = 0
    total_malware = 100
    total_time = 0
    cnt_time = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            if apk.number_of_queries > 1:
                print(apk.number_of_queries)
            total_ec += apk.percentage_increasing_size
            total_no_query += apk.number_of_queries            
            no_detected += 1
            if apk.execution_time > 1:
                total_time += apk.execution_time
                cnt_time += 1    
   
    avg_total_no_query_ESETNOD32 = total_no_query/no_detected       
    er_evadedroid_ESETNOD32 = (no_detected/(len(apk_name) - cnt_corrupt))*100
    dr_evadedroid_ESETNOD32_before_attack = (len(apk_name)/total_malware)*100
    dr_evadedroid_ESETNOD32_after_attack = ((len(apk_name) - no_detected)/total_malware)*100
    avg_execution_time_ESETNOD32 = total_time/cnt_time
    
    total_no_query = 0  
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:            
            total_no_query += (apk.number_of_queries -  avg_total_no_query_ESETNOD32)**2          
            no_detected += 1            
    std_total_no_query_ESETNOD32 = math.sqrt(total_no_query/(no_detected-1))
    
    name = "result_McAfee"
    path = os.path.join(path_base,name)       
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    total_no_query = 0     
    total_ec = 0
    no_detected = 0
    total_malware = 100
    total_time = 0
    cnt_time = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            total_ec += apk.percentage_increasing_size
            total_no_query += apk.number_of_queries            
            no_detected += 1
            if apk.execution_time > 1:
                total_time += apk.execution_time
                cnt_time += 1    
    
    avg_total_no_query_McAfee = total_no_query/no_detected       
    er_evadedroid_McAfee = (no_detected/(len(apk_name) - cnt_corrupt))*100
    dr_evadedroid_McAfee_before_attack = (len(apk_name)/total_malware)*100
    dr_evadedroid_McAfee_after_attack = ((len(apk_name) - no_detected)/total_malware)*100
    avg_execution_time_McAfee = total_time/cnt_time
    
    
    name = "result_Microsoft"
    path = os.path.join(path_base,name)       
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    total_no_query = 0     
    total_ec = 0
    no_detected = 0
    total_malware = 100
    total_time = 0
    cnt_time = 0
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            total_ec += apk.percentage_increasing_size
            if apk.number_of_queries > 1:
                print(apk.number_of_queries)
            total_no_query += apk.number_of_queries            
            no_detected += 1
            if apk.execution_time > 1:
                total_time += apk.execution_time
                cnt_time += 1    
    
    avg_total_no_query_Microsoft = total_no_query/no_detected       
    er_evadedroid_Microsoft = (no_detected/(len(apk_name) - cnt_corrupt))*100
    dr_evadedroid_Microsoft_before_attack = (len(apk_name)/total_malware)*100
    dr_evadedroid_Microsoft_after_attack = ((len(apk_name) - no_detected)/total_malware)*100
    avg_execution_time_Microsoft = total_time/cnt_time
    
    total_no_query = 0  
    for app in apk_name:
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:            
            total_no_query += (apk.number_of_queries -  avg_total_no_query_Microsoft)**2          
            no_detected += 1            
    std_total_no_query_Microsoft = math.sqrt(total_no_query/(no_detected-1))
    
    name = "result_Symantec"
    path = os.path.join(path_base,name)       
    apk_name = os.listdir(path)
    cnt_corrupt = 0
    total_no_query = 0     
    total_ec = 0
    no_detected = 0
    total_malware = 100   
    total_time = 0
    cnt_time = 0
    for app in apk_name:        
        apk_info_path = os.path.join(path,app)
        with open(apk_info_path , 'rb') as f:
            apk = pickle.load(f)
        if apk.intact_due_to_soot_error == 1:
            cnt_corrupt += 1
        if apk.adv_malware_label == 0:
            total_ec += apk.percentage_increasing_size
            total_no_query += apk.number_of_queries            
            no_detected += 1
            if apk.execution_time > 1:
                total_time += apk.execution_time
                cnt_time += 1    
   
    avg_total_no_query_Symantec = total_no_query/no_detected       
    er_evadedroid_Symantec = (no_detected/(len(apk_name) - cnt_corrupt))*100
    dr_evadedroid_Symantec_before_attack = (len(apk_name)/total_malware)*100
    dr_evadedroid_Symantec_after_attack = ((len(apk_name) - no_detected)/total_malware)*100
    avg_execution_time_Symantec = total_time/cnt_time    
   
    
    print("ER - kaspersky: %f     ESETNOD32: %f     McAfee: %f     Microsoft: %f     Symantec: %f"%(er_evadedroid_kaspersky,er_evadedroid_ESETNOD32,er_evadedroid_McAfee,er_evadedroid_Microsoft,er_evadedroid_Symantec))
    print("DR-. - kaspersky: %f     ESETNOD32: %f     McAfee: %f     Microsoft: %f     Symantec: %f"%(dr_evadedroid_kaspersky_before_attack,dr_evadedroid_ESETNOD32_before_attack,dr_evadedroid_McAfee_before_attack,dr_evadedroid_Microsoft_before_attack,dr_evadedroid_Symantec_before_attack))
    print("DR+. - kaspersky: %f     ESETNOD32: %f     McAfee: %f     Microsoft: %f     Symantec: %f"%(dr_evadedroid_kaspersky_after_attack,dr_evadedroid_ESETNOD32_after_attack,dr_evadedroid_McAfee_after_attack,dr_evadedroid_Microsoft_after_attack,dr_evadedroid_Symantec_after_attack))  
    print("Avg. Execution Time. - kaspersky: %f     ESETNOD32: %f     McAfee: %f     Microsoft: %f     Symantec: %f"%(avg_execution_time_kaspersky,avg_execution_time_ESETNOD32,avg_execution_time_McAfee,avg_execution_time_Microsoft,avg_execution_time_Symantec))    
    print("Avg. No. of Queries. - kaspersky: %f + %f    ESETNOD32: %f + %f    McAfee: %f + %f    Microsoft: %f + %f     Symantec: %f + %f"%(avg_total_no_query_kaspersky,0,avg_total_no_query_ESETNOD32,std_total_no_query_ESETNOD32,avg_total_no_query_McAfee,0,avg_total_no_query_Microsoft,std_total_no_query_Microsoft,avg_total_no_query_Symantec,0))    
