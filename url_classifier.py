# -*- coding: utf-8 -*-
"""
Created on Thu Aug  7 20:19:29 2025

@author: LEY
"""
from pathlib import Path
import joblib
import pandas as pd

def risk_level(prob):
    if prob >= 0.85:
        return "high"
    elif prob >= 0.5:
        return "medium"
    else:
        return "low"

def url_classifier(df):
    df = df.copy()
    df = df[~df['url'].duplicated()]
    df_38 = df.drop(columns=['short_urls', 'sus_match', 'url', 'count_tld'])
    df_url = df[['url']].reset_index(drop=True)
    
    model_path = Path("URL_classification_model_BENIGN_MALICIOUS_3000k-Model_2-38_features-2nd_model.json")
    model_2 = joblib.load(model_path)
    
    # Predict labels and probabilities
    y_pred = model_2.predict(df_38)
    mal_prob = model_2.predict_proba(df_38)[:, 1]  # Probability of class 1 (malicious)
    
    # Combine results
    df_res = pd.DataFrame({
        "url": df_url["url"],
        "prediction": y_pred,
        "malicious_probability": mal_prob  # Optional: round for readability
    })
    
    df_res['prediction_label'] = df_res['prediction'].apply(lambda i : 'benign' if i == 0 else 'malicious')
    df_res['malicious_probability'] = df_res['malicious_probability'].apply(lambda x: round(x, 4))
    df_res['risk_level'] = df_res['malicious_probability'].apply(risk_level)
    
    return df_res



