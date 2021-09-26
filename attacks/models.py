# -*- coding: utf-8 -*-

"""
preparing the classification models for the EvadeDroid's pipeline.
~~~~~~~~

This module that is originally created in [1] has been modified and extended a lot for using in EvadeDroid.

[2] Intriguing Properties of Adversarial ML Attacks in the Problem Space 
    [S&P 2020], Pierazzi et al.


"""
import logging
import numpy as np
import os
import pickle
import ujson as json
from collections import OrderedDict
from sklearn.feature_extraction import DictVectorizer
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import auc
from sklearn.metrics import roc_curve
import  random
import matplotlib.pyplot as plt
import lib.secsvm
from lib.utils import blue, red
from settings import config



class SVMModel:
    """Base class for SVM-like classifiers."""

    def __init__(self, malware_detector, dataset_accessible, X_filename, y_filename, meta_filename, num_features=None, X_filename_accessible = None, y_filename_accessible = None, meta_filename_accessible = None,append=None):
        self.dataset_accessible = dataset_accessible
        self.X_filename = X_filename
        self.y_filename = y_filename
        self.meta_filename = meta_filename
        self._num_features = num_features
        self.clf, self.vec = None, None
        self.column_idxs = []
        self.X_train, self.y_train, self.m_train = [], [], []
        self.X_test, self.y_test, self.m_test = [], [], []
        self.feature_weights, self.benign_weights, self.malicious_weights = [], [], []
        self.weight_dict = OrderedDict()
        
        #Extended parts
        self.X_filename_accessible = X_filename_accessible
        self.y_filename_accessible = y_filename_accessible
        self.meta_filename_accessible = meta_filename_accessible
        self.malware_detector = malware_detector
        self.append = append

    def generate(self, save=True):
        """Load and fit data for new model."""
        logging.debug(blue('No saved models found, generating new model...'))
       
        #Extended load_features
        X_train, X_test, y_train, y_test, m_train, m_test, self.vec = load_features(
            self.X_filename, self.y_filename, self.meta_filename, False, self.X_filename_accessible,self.y_filename_accessible, self.meta_filename_accessible,self.append)


        self.column_idxs = self.perform_feature_selection(X_train, y_train)

        self.X_train = X_train[:, self.column_idxs]
        self.X_test = X_test[:, self.column_idxs]
        self.y_train, self.y_test = y_train, y_test       
        self.m_train, self.m_test = m_train, m_test       
        
        if self.dataset_accessible == False:
            self.clf = self.fit(self.X_train, self.y_train)        
            
        self.vec.feature_names_ = [self.vec.feature_names_[val] for i,val in enumerate(self.column_idxs)]        
        if save:
            self.save_to_file()
    
    #New method in extended version of module
    def generate_mamadroid(self, save=True, no_training_sample=8000):
        """Load and fit data for new model."""
        logging.debug(blue('No saved models found, generating new model...'))       
        X_train, X_test, y_train, y_test,m_train, m_test, self.vec = load_features_mamadroid(
            self.X_filename, self.y_filename, self.meta_filename,no_training_sample)        

        self.X_train = X_train
        self.X_test = X_test
        self.y_train, self.y_test = y_train, y_test
        self.m_train = m_train
        self.m_test = m_test
        
        knn = KNeighborsClassifier(n_neighbors=5)
        self.clf = knn.fit(X_train, y_train)#self.fit(self.X_train, self.y_train)           
        
        if save:
            self.save_to_file()

    #New method in extended version of module
    def generate_roc_curve(self, save=False):
        """Load and fit data for new model."""
        logging.debug(blue('No saved models found, generating new model...'))
        
        X_train, X_test, y_train, y_test, m_train, m_test, self.vec = load_features(
            self.X_filename, self.y_filename, self.meta_filename, False, self.X_filename_accessible,self.y_filename_accessible, self.meta_filename_accessible,self.append)

        self.column_idxs = self.perform_feature_selection(X_train, y_train)
        self.X_train = X_train[:, self.column_idxs]
        self.X_test = X_test[:, self.column_idxs]
        self.y_train, self.y_test = y_train, y_test        
        self.m_train, self.m_test = m_train, m_test        
            
        self.vec.feature_names_ = [self.vec.feature_names_[val] for i,val in enumerate(self.column_idxs)]
        
        if save:
            self.save_to_file()
            
    def dict_to_feature_vector(self, d):
        """Generate feature vector given feature dict."""
        return self.vec.transform(d)[:, self.column_idxs]  

    def perform_feature_selection(self, X_train, y_train):
        """Perform L2-penalty feature selection."""
        if self._num_features is not None:
            logging.info(red('Performing L2-penalty feature selection'))
            selector = LinearSVC(C=1)
            selector.fit(X_train, y_train)

            cols = np.argsort(np.abs(selector.coef_[0]))[::-1]
            cols = cols[:self._num_features]
        else:
            cols = [i for i in range(X_train.shape[1])]
        return cols

    def save_to_file(self):
        with open(self.model_name, 'wb') as f:
            pickle.dump(self, f) 
     


class SVM(SVMModel):
    """Standard linear SVM using scikit-learn implementation."""

    def __init__(self, malware_detector, dataset_accessible, X_filename, y_filename, meta_filename, num_features=None, X_filename_accessible = None, y_filename_accessible = None, meta_filename_accessible = None,append = None):
        super().__init__(malware_detector, dataset_accessible, X_filename, y_filename, meta_filename, num_features, X_filename_accessible, y_filename_accessible, meta_filename_accessible,append)
        self.model_name = self.generate_model_name()

    def fit(self, X_train, y_train):
        logging.debug(blue('Creating model'))
        clf = LinearSVC(C=0.5)
        #clf = LinearSVC(C=1)
        clf.fit(X_train, y_train)
        return clf

    def generate_model_name(self):
        if self.malware_detector == "MaMaDroid":
            model_name = 'svm-mamadroid'
        else:
            model_name = 'svm'
        model_name += '.p' if self._num_features is None else '-f{}.p'.format(self._num_features)
        if self.dataset_accessible == True:
            return os.path.join(config['models_accessible'], model_name)
        else:
            return os.path.join(config['models_inaccessible'], model_name)


class SecSVM(SVMModel):
    """Secure SVM variant using a PyTorch implementation."""

    def __init__(self, malware_detector,dataset_accessible, X_filename, y_filename, meta_filename, num_features=None,
                 secsvm_k=0.2, secsvm=False, secsvm_lr=0.0001,
                 secsvm_batchsize=1024, secsvm_nepochs=75, seed_model=None, X_filename_accessible = None, y_filename_accessible = None, meta_filename_accessible = None,append = None):
        super().__init__(malware_detector,dataset_accessible, X_filename, y_filename, meta_filename, num_features, X_filename_accessible, y_filename_accessible, meta_filename_accessible,append)
        self._secsvm = secsvm
        self._secsvm_params = {
            'batchsize': secsvm_batchsize,
            'nepochs': secsvm_nepochs,
            'lr': secsvm_lr,
            'k': secsvm_k
        }
        self._seed_model = seed_model
        self.model_name = self.generate_model_name()

    def fit(self, X_train, y_train):
        logging.debug(blue('Creating model'))
        clf = lib.secsvm.SecSVM(lr=self._secsvm_params['lr'],
                                batchsize=self._secsvm_params['batchsize'],
                                n_epochs=self._secsvm_params['nepochs'],
                                K=self._secsvm_params['k'],
                                seed_model=self._seed_model)
        clf.fit(X_train, y_train)
        return clf

    def generate_model_name(self):
        dataset_accessible = "dataset_accessible"
        if self.dataset_accessible == False:
            dataset_accessible = "dataset_inaccessible"
        model_name = 'secsvm-k{}-lr{}-bs{}-e{}-{}'.format(
            self._secsvm_params['k'],
            self._secsvm_params['lr'],
            self._secsvm_params['batchsize'],
            self._secsvm_params['nepochs'],
            dataset_accessible)
        if self._seed_model is not None:
            model_name += '-seeded'
        model_name += '.p' if self._num_features is None else '-f{}.p'.format(self._num_features)
        if self.dataset_accessible == True:
            return os.path.join(config['models_accessible'], model_name)
        else:
            return os.path.join(config['models_inaccessible'], model_name)
    
def load_from_file(model_filename):
    logging.debug(blue(f'Loading model from {model_filename}...'))
    with open(model_filename, 'rb') as f:
        return pickle.load(f)


def load_features(X_filename, y_filename, meta_filename, load_indices=True, X_filename_accessible = None, y_filename_accessible = None, meta_filename_accessible = None,append = None):
      
    #Note: X_dataset_accessible is the same as test dataset for inaccessible modle
    
    #with open(X_filename, 'rt') as f':
    with open(X_filename, 'rb') as f:
        X = json.load(f) 
    X_accessible = []
    if X_filename_accessible is not None:
        with open(X_filename_accessible, 'rt') as f:
            X_accessible = json.load(f)  
    X_total = X + X_accessible 
    
    if append != None:
        path = os.path.join(config['features_inaccessible'],'sub_dataset-X-append.json')
        with open(path, 'rt') as f:
            X_append = json.load(f)  
        X_total = X + X_append 
   
        
    with open(y_filename, 'rt') as f:
        y = json.load(f)      
    
    y_accessible = []
    if y_filename_accessible is not None:
        with open(y_filename_accessible, 'rt') as f:
            y_accessible = json.load(f)  
    
    y_total = y + y_accessible
    
    if append != None:
        path = os.path.join(config['features_inaccessible'],'sub_dataset-Y-append.json')
        with open(path, 'rt') as f:
            y_append = json.load(f)  
        y_total = y + y_append     
      
    with open(meta_filename, 'rt') as f:
        meta = json.load(f)        
    
    meta_accessible = []
    if meta_filename_accessible is not None:
       with open(meta_filename_accessible, 'rt') as f:
           meta_accessible = json.load(f)  
    
    meta_total = meta + meta_accessible
    
    
    if append != None:
        path = os.path.join(config['features_inaccessible'],'sub_dataset-meta-append.json')
        with open(path, 'rt') as f:
            meta_append = json.load(f)  
        meta_total = meta + meta_append 
   
    
    train_idxs = list(range(0,len(X)))
    test_idxs = list(range(len(X),len(X) + len(X_accessible)))
    
    X, y, vec = vectorize(X_total, y_total) 
    
    
    X_train = X[train_idxs]
    X_test = X[test_idxs]
    y_train = y[train_idxs]
    y_test = y[test_idxs]
    m_train = [meta_total[i] for i in train_idxs]
    m_test = [meta_total[i] for i in test_idxs]
    
    for item in enumerate(m_train):
        if X_filename_accessible is None:
            item[1]["sample_path"] = os.path.join(config["apks_inaccessible"],item[1]["pkg_name"] + '.apk')        
    
    for item in enumerate(m_test):
        if X_filename_accessible is None:
            item[1]["sample_path"] = os.path.join(config["apks_inaccessible"],item[1]["pkg_name"] + '.apk')        
   
    return X_train, X_test, y_train, y_test, m_train, m_test, vec

#New method in extended version of module
def load_features_mamadroid(X_filename, y_filename,meta_filename,no_training_sample):
      
    path = X_filename   
    with open(path, 'rb') as f:
        apks_path_for_mamadroid = pickle.load(f) 
    
    feature_names_ = apks_path_for_mamadroid.pop(0) 
    app_names = [os.path.splitext(item[0])[0] +'.apk' for item in apks_path_for_mamadroid]
    app_idx = [idx for idx,item in enumerate(meta_filename) if os.path.basename(item['sample_path']) in app_names]  
    
    label = dict()
    for i in app_idx:
        label[os.path.basename(meta_filename[i]['sample_path'])] = y_filename[i]   

    dataset_idx = range(0,len(apks_path_for_mamadroid))
    train_idx = random.sample(dataset_idx,no_training_sample)
    X_train = np.array([np.array(item[1:]) for idx,item in enumerate(apks_path_for_mamadroid) if idx in train_idx])
    app_X_train = [os.path.splitext(item[0])[0] +'.apk' for idx,item in enumerate(apks_path_for_mamadroid) if idx in train_idx]
    y_train = list()
    for i in range(0,len(X_train)):        
        y_train.append(label[app_X_train[i]])
    
    
    m_train = app_X_train#[item for item in meta_filename if os.path.basename(item['sample_path']) in app_X_train]
    #m_train = [np.array(item) for item in m_train_temp]
    
    test_idx = [i for i in dataset_idx if i not in train_idx]
    X_test = np.array([np.array(item[1:]) for idx,item in enumerate(apks_path_for_mamadroid) if idx in test_idx])
    app_X_test = [os.path.splitext(item[0])[0] +'.apk' for idx,item in enumerate(apks_path_for_mamadroid) if idx in test_idx]
    
       
    y_test = list()
    for i in range(0,len(X_test)):     
        if i == 71:
            print(i)
        y_test.append(label[app_X_test[i]])   
    
    m_test = app_X_test#[item for item in meta_filename if os.path.basename(item['sample_path']) in app_X_test]
    #m_test = [np.array(item) for item in m_test_temp]
    
    return X_train, X_test, y_train, y_test,m_train,m_test, feature_names_


def create_roc_curve():   
    model_main = SVM("Drebin", False, config['X_dataset_inaccessible'], config['Y_dataset_inaccessible'],
                                  config['meta_inaccessible'])
    model_main.generate_roc_curve()
    
    plt.figure(figsize=(10,10))
    
    plot_roc_curve(model_main,"Drebin")
    plot_roc_curve(model_main,"Sec-SVM")
    
    model_main = load_from_file(model_main.model_name)
    path = os.path.join(config['mamadroid'],'Features/Families/dataset_inaccessible.p')    
    model_mamadroid = SVM("MaMaDroid", False, path, model_main.y_train,
                         model_main.m_train)  
             
    if os.path.exists(model_mamadroid.model_name):
         model_mamadroid = load_from_file(model_mamadroid.model_name)
    else:
         model_mamadroid.generate_mamadroid(no_training_sample=11050)  
    model_main = model_mamadroid
    plot_roc_curve(model_main,"MaMaDroid")
    
    plt.grid()
    plt.xticks(fontsize=15,fontname="Times New Roman")
    plt.yticks(fontsize=15,fontname="Times New Roman")
    import matplotlib.font_manager as font_manager
    font = font_manager.FontProperties(family='Times New Roman',
                               weight='bold',
                               style='normal', size=16)
    plt.legend(prop=font) 
    plt.savefig("Results/ROC.jpg", format='jpg', dpi=800)  
    plt.show()

def plot_roc_curve(model,malware_detector):
    cv = StratifiedKFold(n_splits=10)
    if malware_detector == "Drebin":
        classifier  = LinearSVC(C=1)
    elif malware_detector == "Sec-SVM":
        classifier = lib.secsvm.SecSVM(lr=0.0001,
                                batchsize=1024,
                                n_epochs=20,
                                K=0.2,
                                seed_model=None)
    elif malware_detector == "MaMaDroid":
        classifier = KNeighborsClassifier(n_neighbors=5)    
    tprs = []
    aucs = []
    mean_fpr = np.linspace(0, 1, 100)
    
    i = 0
    X_train_res = model.X_train
    if malware_detector == "MaMaDroid":
        y_train_res = np.array(model.y_train)
    else:
        y_train_res = model.y_train
    for train, test in cv.split(X_train_res, y_train_res):
        classifier.fit(X_train_res[train], y_train_res[train])
        if malware_detector == "MaMaDroid":
            probas_ = classifier.predict_proba(X_train_res[test])
            probas_ = [item[1] for item in probas_]
        else:
            probas_ = classifier.decision_function(X_train_res[test])        
        fpr, tpr, thresholds = roc_curve(y_train_res[test], probas_)
        tprs.append(np.interp(mean_fpr, fpr, tpr))
        tprs[-1][0] = 0.0
        roc_auc = auc(fpr, tpr)
        aucs.append(roc_auc)        
        i += 1
        print("i: ", i)
    if malware_detector == "Drebin":
        plt.plot([0, 1], [0, 1], linestyle='--', lw=2, color='r',
                 label='Random Chances', alpha=.8)
    
    mean_tpr = np.mean(tprs, axis=0)
    mean_tpr[-1] = 1.0    
    
    std_tpr = np.std(tprs, axis=0)
    tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
    tprs_lower = np.maximum(mean_tpr - std_tpr, 0)
    
    if malware_detector == "Drebin":
        plt.plot(mean_fpr, mean_tpr, color='b',
             label=r'DREBIN',
             lw=2, alpha=.8)
        
        plt.fill_between(mean_fpr, tprs_lower, tprs_upper, color='b', alpha=.2)
    elif malware_detector == "Sec-SVM":
        plt.plot(mean_fpr, mean_tpr, color='g',
             label=r'Sec-SVM',
             lw=2, alpha=.8)
        
        plt.fill_between(mean_fpr, tprs_lower, tprs_upper, color='g', alpha=.2)
    else:        
        plt.plot(mean_fpr, mean_tpr, color='m',
             label=r'MaMaDroid',
             lw=2, alpha=.8)        
        plt.fill_between(mean_fpr, tprs_lower, tprs_upper, color='m', alpha=.2)    
    
    plt.xlim([-0.01, 1.01])
    plt.ylim([-0.01, 1.01])
    plt.xlabel('False Positive Rate',fontsize=16,fontname="Times New Roman")
    plt.ylabel('True Positive Rate',fontsize=16,fontname="Times New Roman")  
    plt.legend(loc="lower right", prop={'size': 15}) 

def vectorize(X, y):
    vec = DictVectorizer()# DictVectorizer(sparse=False)
    X = vec.fit_transform(X)
    y = np.asarray(y)
    return X, y, vec


    