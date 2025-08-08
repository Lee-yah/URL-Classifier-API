# URL Classifier Features Documentation

This document provides a comprehensive overview of all features extracted by the URL Classifier API for malicious URL detection.

## Overview

The URL Classifier analyzes **38 features** extracted from URLs, categorized into two main types:
- **36 Lexical Features**: Based on URL text analysis
- **2 Host-based Features**: Based on domain registration information

---

## Lexical Features (36)

| # | Feature | Description | Example/Range |
|---|---------|-------------|---------------|
| 1 | `url_length` | Total character count of the URL | `https://example.com/path` → 23 |
| 2 | `url_has_ip` | Whether URL contains IP address instead of domain | `http://192.168.1.1` → 1, `https://google.com` → 0 |
| 3 | `path_length` | Length of the URL path component | `/user/profile/settings` → 21 |
| 4 | `path_to_url_length_ratio` | Ratio of path length to total URL length | Path: 10, URL: 50 → 0.2 |
| 5 | `count_dir` | Number of directory separators (/) in path | `/dir1/dir2/file.html` → 3 |
| 6 | `fd_length` | Length of the first directory name | `/downloads/file.zip` → 10 |
| 7 | `count_embed_domian` | Number of embedded domains in URL | Multiple domains embedded → count |
| 8 | `count_short_url` | Number of URL shortening services detected | `bit.ly`, `tinyurl.com` → count |
| 9 | `short_urls` | List of shortening services found | `['bit.ly', 'goo.gl']` |
| 10 | `count_lowercase` | Number of lowercase letters | 0 to URL length |
| 11 | `lower_case_to_url_length_ratio` | Ratio of lowercase letters to total length | 0.0 to 1.0 |
| 12 | `count_uppercase` | Number of uppercase letters | 0 to URL length |
| 13 | `upper_case_to_url_length_ratio` | Ratio of uppercase letters to total length | 0.0 to 1.0 |
| 14 | `count_digits` | Number of numeric digits | 0 to URL length |
| 15 | `count_letters` | Number of alphabetic characters | 0 to URL length |
| 16 | `digit_to_url_length_ratio` | Ratio of digits to total length | 0.0 to 1.0 |
| 17 | `letters_to_url_length_ratio` | Ratio of letters to total length | 0.0 to 1.0 |
| 18 | `count_spec_char` | Number of special characters | 0 to URL length |
| 19 | `spec_char_to_url_length_ratio` | Ratio of special characters to total length | 0.0 to 1.0 |
| 20 | `count_www` | Occurrences of "www" substring | Count of "www" |
| 21 | `count_dot` | Number of dots/periods | Count of `.` |
| 22 | `count_@` | Number of at symbols | Count of `@` |
| 23 | `count_%` | Number of percent signs | Count of `%` |
| 24 | `count_?` | Number of question marks | Count of `?` |
| 25 | `count_-` | Number of hyphens | Count of `-` |
| 26 | `count_=` | Number of equal signs | Count of `=` |
| 27 | `count_#` | Number of hash/pound signs | Count of `#` |
| 28 | `count_;` | Number of semicolons | Count of `;` |
| 29 | `count_undersc` | Number of underscores | Count of `_` |
| 30 | `http_or_https` | Protocol type identification | 1 = HTTP, 2 = HTTPS, -1 = Other |
| 31 | `entropy` | URL randomness measure | 0.0 to 5.0+ (higher = more random) |
| 32 | `tld_len` | Top-level domain length | `.com` → 3, `.education` → 9 |
| 33 | `host_length` | Total hostname length | `subdomain.example.com` → 19 |
| 34 | `count_host_hyphen` | Hyphens in hostname | `sub-domain.example.com` → 1 |
| 35 | `count_host_underscore` | Underscores in hostname | `sub_domain.example.com` → 1 |
| 36 | `count_subdomains` | Number of subdomains | `mail.subdomain.example.com` → 2 |

**Note**: `count_tld` was removed due to high correlation with `count_embed_domain` feature.

---

## Host-based Features (2)

| # | Feature | Description | Values | Notes |
|---|---------|-------------|--------|-------|
| 37 | `days_since_reg` | Days since domain registration | Positive integer or -1 | -1 = Unable to determine |
| 38 | `days_since_exp` | Days since domain expiration | Positive/Negative integer or -1 | Negative = Expired |

---

## Feature Analysis and References

### Entropy Scale Reference:
- **0.0 - 1.0**: Extremely Low (repetitive patterns)
- **1.0 - 2.0**: Very Low (simple, predictable)
- **2.0 - 3.0**: Low to Normal (typical websites)
- **3.0 - 4.0**: Normal to High (complex URLs)
- **4.0 - 4.5**: High (very random, potentially suspicious)
- **4.5 - 5.0**: Very High (extremely random, likely malicious)
- **5.0+**: Maximum (perfect randomness, highly suspicious)

### URL Shortening Services Detected:
The system detects over 50 shortening services including: `bit.ly`, `goo.gl`, `tinyurl.com`, `t.co`, `shorte.st`, `ow.ly`, `is.gd`, `cli.gs`, and many others.

### Suspicious Word Categories:
- **Authentication**: login, signin, verify, account, secure, auth
- **Financial**: bank, payment, invoice, billing, transaction, refund
- **Alerts**: alert, security, suspend, locked, warning, urgent, confirm
- **Downloads**: download, attachment, document, pdf, zip, exe, payload
- **Offers**: free, gift, bonus, offer, promo, win, prize, survey, lucky
- **Redirects**: redirect, track, click, url, out, go, link, jump
- **Support**: support, help, service, desk, fix, repair, update

### Domain Age Interpretation:
- **Very New** (0-30 days): Higher risk, common for malicious domains
- **New** (31-365 days): Moderate risk, monitor other features
- **Established** (1+ years): Lower risk, legitimate businesses
- **Old** (5+ years): Very low risk, well-established domains

### Expiration Analysis:
- **Far Future** (1+ years): Well-maintained, legitimate
- **Near Future** (30-365 days): Normal, monitor renewal
- **Soon** (0-30 days): May indicate abandonment
- **Expired** (Negative values): High risk, potentially compromised

---

## Feature Engineering Notes

### Performance Considerations:
- **Fast Features**: Lexical analysis (computed instantly)
- **Slow Features**: Host-based features (require network queries with 4-second delays)

---

The model was trained on 2 datasets, each containing 3000 URLs with balanced representation of benign and malicious examples.

---

## Usage in API

All features are automatically extracted when a URL is submitted to the `/predict/` endpoint. Users don't need to manually calculate these features - the API handles all feature extraction internally.

