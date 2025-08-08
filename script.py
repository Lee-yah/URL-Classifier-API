# -*- coding: utf-8 -*-
"""
Created on Thu Aug  7 19:13:51 2025

@author: LEY
"""
UTIL_DIR = 'utils/'

from flask import request
import sys
sys.path.append(UTIL_DIR)
import url_feature_utils as urlftils
import pandas as pd


def populate_38_features(df):
    df = df.copy()
    df_lex = urlftils.url_37_lexical_features(df)   
    df_host = urlftils.url_2_host_based_features(df)
    
    df = pd.merge(df_lex ,df_host , on=['url'], how='left', suffixes=['', '_updated'])
    
    return df

def get_urls():
    err_mess = { "error": "Cannot extract data. Use correct syntax or keyword" }
    
    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form

        if 'urls' in data and isinstance(data['urls'], list):
            urls = data['urls']
        elif 'url' in data and isinstance(data['url'], str):
            urls = [data['url']]
        else:
            urls = err_mess
    else:
        url = request.args.get('url')
        urls = [url] if url else err_mess

    return urls

