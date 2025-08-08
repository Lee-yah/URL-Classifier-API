# -*- coding: utf-8 -*-
"""
Created on Thu Aug  7 17:32:33 2025

@author: LEY
"""

from flask import Flask, jsonify, render_template, request
import pandas as pd
import script as urlf
import url_classifier as malwhere

app = Flask(__name__)

@app.route('/')
def home():
    # Get the base URL dynamically
    base_url = request.host_url.rstrip('/')
    
    # Determine environment
    is_production = os.environ.get('DEVELOPMENT_ENVIRONMENT') == 'production'
    environment = "Production" if is_production else "Local Development"
    
    return render_template('home.html', base_url=base_url, environment=environment)

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
    import os
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('DEVELOPMENT_ENVIRONMENT') != 'production'
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
    
