# -*- coding: utf-8 -*-

"""
Experimental settings for the EvadeDroid's pipeline.
"""
import os

_absolute_project_path = '/home/hamid/Projects/end-to-end_black-box_evasion_attack'
_absolute_java_components_path = '/home/hamid/Projects/end-to-end_black-box_evasion_attack/java-components/build'


def project(base):
    return os.path.join(_absolute_project_path, base)


def java_components(base):
    return os.path.join(_absolute_java_components_path, base)


config = {    
    'project_root': _absolute_project_path,
    
    #data: apks and features
    'apks_accessible': project('data/apks/accessible/'),
    'apks_inaccessible': project('data/apks/inaccessible/'),    
    'features_accessible': project('data/features/accessible/'),
    'features_inaccessible': project('data/features/inaccessible/'),   
    'features' : project('data/features/'),  
    'apks': project('data/apks/'),  
    'stored_components': project('data/stored-components/'),    
    'mamadroid':project('mamadroid'),      
    'models_accessible': project('data/models/accessible/'),
    'models_inaccessible': project('data/models/inaccessible/'),
    'total_dataset': project('data/features/total/'),    
    'X_dataset_accessible': project('data/features/accessible/accessible-dataset-X.json'),
    'Y_dataset_accessible': project('data/features/accessible/accessible-dataset-Y.json'),
    'meta_accessible': project('data/features/accessible/accessible-dataset-meta.json'),    
    'X_dataset_inaccessible': project('data/features/inaccessible/inaccessible-dataset-X.json'),
    'Y_dataset_inaccessible': project('data/features/inaccessible/inaccessible-dataset-Y.json'),
    'meta_inaccessible': project('data/features/inaccessible/inaccessible-dataset-meta.json'),    
    'feature_extractor': '/home/hamid/Projects/feature-extractor',
    'tmp_dir': project('data/stored-components/tmp/'),  
    'goodware_location': project('/data/apk'),

    #software transplantation components
    'soot':java_components('soot/'),   
    'extractor': java_components('extractor.jar'),
    'appgraph': java_components('appgraph.jar'),
    'ice_box': project('/data/stored-components/ice_box/'),
    'android_sdk': '/usr/lib/android-sdk/',
    'java_sdk': '/usr/lib/jvm/java-1.8.0-openjdk-amd64/bin/',    
    'extractor_timeout': 600,
    'template_path': project('data/template'),
    'results_dir': project('/data/stored-components/attack-results'),   
    'indices': project(''),  # only needed if using fixed indices   
    'injector': java_components('injector.jar'),
    'smallinjector': java_components('smallinjector.jar'),
    'template_injector': java_components('templateinjector.jar'),
    'cc_calculator': java_components('cccalculator.jar'),
    'class_lister': java_components('classlister.jar'),
    'classes_file': project('all_classes.txt'),       
    'mined_slices': project('mined-slices'),
    'opaque_pred': project('opaque-preds/sootOutput'),
    'resigner': java_components('apk-signer.jar'),      
    'cc_calculator_timeout': 600,  
    'storage_radix': 0,  # Use if apps are stored with a radix (e.g., radix 3: root/0/0/A/00A384545.apk)
    # Miscellaneous options
    'tries': 1,
    'nprocs_preload': 8,
    'nprocs_evasion': 12,
    'nprocs_transplant': 8
}
