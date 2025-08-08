# -*- coding: utf-8 -*-
"""
Created on Thu Aug  7 17:32:33 2025

@author: LEY
"""

from flask import Flask, jsonify
import pandas as pd
import script as urlf
import url_classifier as malwhere

app = Flask(__name__)

@app.route('/predict/', methods=['GET', 'POST'])
def start():
    
    urls = urlf.get_urls()
    
    if 'error' in urls:
        return urls
        
    df = pd.DataFrame({
        "url": urls
        })
        
    df = urlf.populate_38_features(df)
    prediction = malwhere.url_classifier(df)
    
    return jsonify(prediction.to_dict('records'))

if __name__ == '__main__':
    app.run(debug=True)
    
