# URL Classifier API

A REST API that uses machine learning to classify URLs as benign or malicious. The API analyzes 38 features extracted from URLs to predict their safety level and provides risk assessment.

## Features

- **URL Classification**: Classifies URLs as benign or malicious using a trained machine learning model
- **Risk Assessment**: Provides risk levels (low, medium, high) based on malicious probability
- **Feature Extraction**: Extracts 38 lexical and host-based features from URLs
- **Flexible Input**: Supports single URL or multiple URLs in one request
- **RESTful API**: Easy-to-use REST endpoints with JSON responses

## Installation

### Prerequisites

- Python 3.13 or higher
- pip package manager

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/Lee-yah/URL-Classifier-API.git
   cd URL-Classifier-API
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

The API will be available at `http://localhost:5000`

## API Usage

### Base URL
- **Live API**: Coming soon (will be deployed)
- **Local Testing**: `http://localhost:5000` (see Development section below)

### Endpoint

```
POST/GET /predict/
```

### Request Methods

#### Method 1: GET Request (Single URL)
**Postman Setup:**
- Method: `GET`
- URL: `http://localhost:5000/predict/?url=https://example.com`

#### Method 2: POST Request (Single URL - JSON)
**Postman Setup:**
- Method: `POST`
- URL: `http://localhost:5000/predict/`
- Headers: `Content-Type: application/json`
- Body (raw JSON):
```json
{
  "url": "https://example.com"
}
```

#### Method 3: POST Request (Multiple URLs - JSON)
**Postman Setup:**
- Method: `POST`
- URL: `http://localhost:5000/predict/`
- Headers: `Content-Type: application/json`
- Body (raw JSON):
```json
{
  "urls": [
    "https://example.com",
    "https://test.com", 
    "http://suspicious-site.com"
  ]
}
```

#### Method 4: POST Request (Form Data)
**Postman Setup:**
- Method: `POST`
- URL: `http://localhost:5000/predict/`
- Body: `x-www-form-urlencoded`
- Key-Value: 
  - Key: `url`
  - Value: `https://example.com`

### Response Format

#### Successful Response

```json
[
  {
    "url": "https://example.com",
    "prediction": 0,
    "malicious_probability": 0.1234,
    "prediction_label": "benign",
    "risk_level": "low"
  },
  {
    "url": "http://suspicious-site.com",
    "prediction": 1,
    "malicious_probability": 0.8765,
    "prediction_label": "malicious",
    "risk_level": "high"
  }
]
```

#### Error Response

```json
{
  "error": "Cannot extract data. Use correct syntax or keyword"
}
```

### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `url` | string | The analyzed URL |
| `prediction` | integer | Binary prediction (0 = benign, 1 = malicious) |
| `malicious_probability` | float | Probability of the URL being malicious (0.0-1.0) |
| `prediction_label` | string | Human-readable prediction ("benign" or "malicious") |
| `risk_level` | string | Risk assessment ("low", "medium", "high") |

### Risk Level Classification

- **Low Risk**: malicious_probability < 0.5
- **Medium Risk**: 0.5 ≤ malicious_probability < 0.85
- **High Risk**: malicious_probability ≥ 0.85

## Model Information

The API uses a trained machine learning model that analyzes 39 features extracted from URLs.

### Feature Categories:
- **37 Lexical Features**: URL structure, character analysis, and content patterns
- **2 Host-based Features**: Domain registration and expiration information

For detailed documentation of all features, see [FEATURES.md](FEATURES.md).

### Key Feature Types:
- URL length and structure analysis
- Character frequency analysis
- Domain and subdomain characteristics
- Path and query parameter analysis
- Protocol and scheme validation
- Suspicious content detection
- Domain registration information

## Development

### Environment Configuration

#### Local Development
The application runs in debug mode by default for easy testing and development.

#### Production Deployment
The project owner will handle production deployment. The application is designed to automatically adapt to production environments when deployed.

**Note**: This is a machine learning research project. For questions about the live API or commercial use, please contact the project owner.

## Dependencies

Key dependencies include:
- **Flask**: Web framework
- **pandas**: Data manipulation
- **scikit-learn**: Machine learning model loading
- **python-whois**: Domain information retrieval

See `requirements.txt` for the complete list.

## Support

For issues and questions, please open an issue on the GitHub repository.

---

**Note**: This API is designed for educational and research purposes. For production use, consider implementing additional security measures, rate limiting, and input validation.
