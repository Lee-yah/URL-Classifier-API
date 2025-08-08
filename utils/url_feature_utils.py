# -*- coding: utf-8 -*-
"""
Created on Wed Jul 30 22:29:18 2025

@author: LEY
"""

import os
import pandas as pd
import ipaddress
from urllib.parse import urlparse
import re
import math
from collections import Counter
import tldextract

import whois #get hostname related info (domain,subdomain..etc)
from datetime import datetime #get today's date
import time #time.sleep

from tqdm import tqdm

#FUNCTIONS
#37 lexical features
def has_http_or_https(url):
    return 1 if url.startswith(('http://', 'https://')) else 0


def url_has_ip(url):
    isUrlhasHttpS = has_http_or_https(url)
    if isUrlhasHttpS:
        h = (urlparse(url).hostname or '').strip('[]')
        try:
            ipaddress.ip_address(h)
            return 1
        except ValueError:
            return 0
        #except: return 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}|([a-fA-F0-9:]{2,})', h) else 0
    else:
        return -1
    
def path_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath)
    except:
        return -1
    
def path_to_url_length_ratio(url):
    try:
        path_len = path_length(url)
        url_len = len(str(url))
        ratio = path_len/url_len
        return ratio
    except:
        return -1

def no_of_dir(url):
    urlpath = urlparse(url).path
    return urlpath.count('/')

#First Directory Length
def first_dir_length(url):
    url_path = urlparse(url).path
    try:
        parts = url_path.split('/')
        if len(parts) > 0:
            if parts[1]:
                return len(parts[1]) + 1
            return 1
    except:
        return 0
    
def get_urls(url):
    urls = re.findall(r'https?://[^\s?&]+', url)
    return urls
    

def no_of_embed_domain(url):
    try:
        urls = get_urls(url)
        return len(urls) - 1 #subtract for main url
    except:
        return -1
    
def get_all_hostnames(url):
    try:
        urls = re.findall(r'https?://[^\s?&]+', url)
        return [urlparse(u).hostname for u in urls]
    except:
        return -1
    
def count_shortening_service(url):
    hostnames_arr = get_all_hostnames(url)
    pattern = (r'^(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
               r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
               r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
               r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|'
               r'db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|'
               r'q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
               r'prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
               r'link\.zip\.net|buff\.link|clik\.now)$')
    
    matches = [host for host in hostnames_arr if re.match(pattern, host)]
    return [len(matches), matches]
    
def count_lowercase(url):
    lowercase = 0
    for i in url:
        if i.islower():
            lowercase= lowercase + 1
    return lowercase
    
def lower_case_to_url_length_ratio(url):
    try:
        count_lower = count_lowercase(url)
        url_len = len(str(url))
        ratio = count_lower/url_len
        return ratio
    except:
        return -1
    
def count_uppercase(url):
    uppercase = 0
    for i in url:
        if i.isupper():
            uppercase = uppercase + 1
    return uppercase

def upper_case_to_url_length_ratio(url):
    try:
        count_upper = count_uppercase(url)
        url_len = len(str(url))
        ratio = count_upper/url_len
        return ratio
    except:
        return -1

def count_digit(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def count_letter(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

def digit_to_url_length_ratio(url):
    try:
        count_numbers = count_digit(url)
        url_len = len(str(url))
        ratio = count_numbers/url_len
        return ratio
    except:
        return -1
    
def letters_to_url_length_ratio(url):
    try:
        count_letre = count_letter(url)
        url_len = len(str(url))
        ratio = count_letre/url_len
        return ratio
    except:
        return -1

def count_spec_char(url):
    specchar = sum(not c.isalnum() for c in url)
    return specchar

def spec_char_to_url_length_ratio(url):
    try:
        count_special = count_spec_char(url)
        url_len = len(str(url))
        ratio = count_special/url_len
        return ratio
    except:
        return -1

def http_or_https(url):
    urlProtocol = urlparse(url).scheme
    if urlProtocol == 'http':
        return 1
    elif urlProtocol == 'https':
        return 2
    else:
        return -1

def calculate_url_entropy(url):

    if not url:
        return 0
    
    # Count occurrences of each character
    char_counts = Counter(url.lower())  # Convert to lowercase for consistency
    total_chars = len(url)
    
    # Calculate entropy
    entropy = 0
    for count in char_counts.values():
        probability = count / total_chars
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy

# =============================================================================
# Entropy Value Translation Guide:
# Character-Based URL Entropy Ranges:
# 0.0 - 1.0: Extremely Low
#     Translation: Almost no randomness, heavy repetition
#     Examples: "aaaaaaa.com", "1111111.net", "wwwwwww.org"
#     Meaning: Same characters repeated many times
#     Security: Usually safe but could be typosquatting
# 
# 1.0 - 2.0: Very Low
#     Translation: Some variety but still predictable patterns
#     Examples: "simple.com", "test123.net", "basic-site.org"
#     Meaning: Limited character diversity, readable patterns
#     Security: Legitimate websites, low risk
#     
# 2.0 - 3.0: Low to Normal
#     Translation: Moderate randomness, typical web URLs
#     Examples: "google.com", "facebook.com/page", "news-site.com/article"
#     Meaning: Good mix of characters, normal website structure
#     Security: Standard URLs, generally safe
#     
# 3.0 - 4.0: Normal to High
#     Translation: Good randomness, mixed character distribution
#     Examples: "stackoverflow.com/questions/12345", "bit.ly/AbC123"
#     Meaning: Diverse characters, complex URLs or short codes
#     Security: Normal for complex sites, monitor context
#     
# 4.0 - 4.5: High
#     Translation: Very random, unpredictable character patterns
#     Examples: "x7k2m9q8r.com", "site.com/a8f3k2m9q7x1"
#     Meaning: High character diversity, appears randomly generated
#     Security: Potentially suspicious, investigate further
#     
# 4.5 - 5.0: Very High
#     Translation: Extremely random, almost no predictable patterns
#     Examples: "qx8k2m9q7r4z1a5b.net", complex malware C2 domains
#     Meaning: Maximum character randomness
#     Security: High risk, likely malicious or auto-generated
#     
# 5.0+: Maximum
#     Translation: Perfect randomness (rare in real URLs)
#     Examples: Very long URLs with perfectly distributed characters
#     Meaning: Theoretical maximum entropy
#     Security: Extremely suspicious, almost certainly malicious
# =============================================================================
        
def tld_length(url):
    if not url:
            return 0
    extracted = tldextract.extract(url)
    tld = extracted.suffix
    return len(tld) if tld else 0

def count_tld(url):
    if not url:
        return 0

    try:
        urls = get_urls(url)
        if len(urls) == 0:
            return 0

        suffixes = [tldextract.extract(u).suffix for u in urls if u]
        return len(suffixes)

    except Exception:
        return -1

def hostname_length(url):
    if not url:
        return 0
    
    return len(urlparse(url).netloc)

def count_hostname_hyphen(url):
    if not url:
        return 0
    
    hostname = urlparse(url).netloc
    return hostname.count('-')

def count_hostname_underscore(url):
    if not url:
        return 0
    
    hostname = urlparse(url).netloc
    return hostname.count('_')
    
def get_subdomain(url):
    ext = tldextract.extract(url)
    return ext.subdomain or None

def count_subdomains(url):
    if not url:
        return 0
    
    try:
        subdomain = get_subdomain(url)
        subdomains = subdomain.split('.')
        return len(subdomains)
    except:
        return -1
    
def suspicious_words(url):
    pattern = re.compile(
        r"^(login|signin|verify|account|secure|auth|update|credentials|"
        r"bank|payment|invoice|billing|transaction|refund|"
        r"alert|security|suspend|locked|warning|urgent|confirm|"
        r"download|attachment|document|pdf|zip|exe|payload|"
        r"free|gift|bonus|offer|promo|win|prize|survey|lucky|anniversary|"
        r"redirect|track|click|url|out|go|r|link|jump|"
        r"support|help|service|desk|fix|repair|update|"
        r"ebayisapi|webscr|porn)$",
        re.IGNORECASE
    )
    
    # Replace non-letters with space, then split
    url_arr = re.sub(r'[^A-Za-z]', ' ', url).split()
    
    match = [u for u in url_arr if pattern.search(u)]
    
    if match:
        return [1, match]
    else:
        return [0, []]
    
#Host based

def days_since_registration(url, who_res=None):
    time.sleep(4)
    try:
        if who_res is None:
            domain = urlparse(url).netloc
            who = whois.whois(domain)
        else:
            who = who_res
        cr_date= who.creation_date
        
        if isinstance(cr_date, list):
            cr_date = cr_date[0]
            
        if cr_date is None:
            return -1
        
        cr_date = cr_date.date()
        current_date = datetime.today().date()
        url_age = (current_date - cr_date).days

        return url_age
    except Exception as e:
        print(f"Error: {e}")
        return -1

def days_since_expiration(url, who_res=None):
    time.sleep(4)
    try:
        if who_res is None:
            domain = urlparse(url).netloc
            who = whois.whois(domain)
        else:
            who = who_res
        ex_date= who.expiration_date
        
        if isinstance(ex_date, list):
            ex_date = ex_date[0]
            
        if ex_date is None:
            return -1

        ex_date = ex_date.date()
        current_date = datetime.today().date()
        url_ex_age = (current_date - ex_date).days

        return url_ex_age
    except Exception as e:
        print(f"Error: {e}")
        return -1

    
def url_37_lexical_features(df):
    df = df.copy()
    #Feature1
    #URL Length
    df['url_length'] = df['url'].apply(lambda i: len(str(i)))
    #Feature2
    #Use of IP
    df['url_has_ip'] = df['url'].apply(lambda i: url_has_ip(i))
    #Feature3
    #URLPath
    df['path_length'] = df['url'].apply(lambda i: path_length(i))
    #Feature4
    #path_to_url length_ratio
    df['path_to_url_length_ratio'] =  df['url'].apply(lambda i: path_to_url_length_ratio(i))
    #Feature5
    #count_dir
    df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))
    #Feature6
    #first directory length
    df['fd_length'] = df['url'].apply(lambda i: first_dir_length(i))
    #Feature7
    df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed_domain(i))
    #Feature8
    #use shortening services
    df[['count_short_url', 'short_urls']] = df['url'].apply(lambda i: pd.Series(count_shortening_service(i)))
    #Feature9
    #count-lowercase
    df['count_lowercase']= df['url'].apply(lambda i: count_lowercase(i))
    #Feature10
    #lowercase to url length ratio
    df['lower_case_to_url_length_ratio'] = df['url'].apply(lambda i: lower_case_to_url_length_ratio(i))
    #Feature11
    #count uppercase
    df['count_uppercase']= df['url'].apply(lambda i: count_uppercase(i))
    #Feature12
    #uppercase to url length ratio
    df['upper_case_to_url_length_ratio'] = df['url'].apply(lambda i: upper_case_to_url_length_ratio(i))
    #Feature13
    #count digits
    df['count_digits']= df['url'].apply(lambda i: count_digit(i))
    #Feature14
    #count letters
    df['count_letters']= df['url'].apply(lambda i: count_letter(i))
    #Feature15
    #digits to url length ratio
    df['digit_to_url_length_ratio'] = df['url'].apply(lambda i: digit_to_url_length_ratio(i))
    #Feature16
    #letters to url length ratio
    df['letters_to_url_length_ratio'] = df['url'].apply(lambda i: letters_to_url_length_ratio(i))
    #Feature17
    #count special characters
    df['count_spec_char']= df['url'].apply(lambda i: count_spec_char(i))
    #Feature18
    #special characters to url length ratio
    df['spec_char_to_url_length_ratio'] = df['url'].apply(lambda i: spec_char_to_url_length_ratio(i))
    #Feature 19-28
    #count WWW (www), DOT (.), AT @, 
    #count percentage (%), question mark (?), hyphen (-), 
    #count equal (=), pound (#), semicolon(;), underscore (_)
    df['count_www'] = df['url'].apply(lambda i: i.count('www'))
    df['count_dot'] = df['url'].apply(lambda i: i.count('.'))
    df['count_@'] = df['url'].apply(lambda i: i.count('@'))
    df['count_%'] = df['url'].apply(lambda i: i.count('%'))
    df['count_?'] = df['url'].apply(lambda i: i.count('?'))
    df['count_-'] = df['url'].apply(lambda i: i.count('-'))
    df['count_='] = df['url'].apply(lambda i: i.count('='))
    df['count_#'] = df['url'].apply(lambda i: i.count('#'))
    df['count_;'] = df['url'].apply(lambda i: i.count(';'))
    df['count_undersc'] = df['url'].apply(lambda i: i.count('_'))
    #Feature 29
    #use http or https
    df['http_or_https'] = df['url'].apply(lambda i: http_or_https(i))
    #Feature 30
    #Entropy measure the randomness of the words
    df['entropy'] = df['url'].apply(lambda i: calculate_url_entropy(i))
    #Feature 31
    #tld length
    df['tld_len'] = df['url'].apply(lambda i: tld_length(i))
    #Feature 32
    #domain count
    df['count_tld'] = df['url'].apply(lambda i: count_tld(i))
    #Feature 33
    # count length
    df['host_length '] = df['url'].apply(lambda i : hostname_length(i))
    #Feature 34
    # count hyphen(-) in hostname
    df['count_host_hyphen'] = df['url'].apply(lambda i: count_hostname_hyphen(i))
    #Feature 35
    # count underscore(_) in hostname
    df['count_host_underscore'] = df['url'].apply(lambda i: count_hostname_underscore(i))
    #Feature 36
    #sub_domain_count
    df['count_subdomains'] = df['url'].apply(lambda i: count_subdomains(i))
    #Feature 37
    df[['sus_words', 'sus_match']] = df['url'].apply(lambda i: pd.Series(suspicious_words(i)))
    
    return df
def days_since_reg_and_exp(url):
    try:
        domain = urlparse(url).netloc
        who = whois.whois(domain)
        url_reg = days_since_registration(url, who)
        url_exp = days_since_expiration(url, who)
    except Exception:
        return [-1, -1]
    
    return [url_reg, url_exp]
    
    
def url_2_host_based_features(df):
    df = df.copy()
    # Enable tqdm integration with Pandas
    tqdm.pandas(desc="Scanning who is")

    #Feature 38 & 39
    #days since reg & days since expired
    df[['days_since_reg', 'days_since_exp']] = df['url'].progress_apply(lambda i: pd.Series(days_since_reg_and_exp(i)))
    
    return df
    