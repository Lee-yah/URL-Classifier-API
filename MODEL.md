# Model Performance and Dataset Information

## Current Model

The API currently uses **Model 3rd**, which was selected as the production model because it achieved the **highest training accuracy of 98.83%** among all three model iterations.

## Dataset Information

### Training Dataset Evolution
- **Model 1st**: 3,000 URLs (1,500 benign + 1,500 malicious) - balanced dataset
- **Model 2nd**: 3,000 URLs (1,500 benign + 1,500 malicious) - new balanced dataset (retrained)
- **Model 3rd**: 6,000 URLs (3,000 benign + 3,000 malicious) - new balanced dataset (retrained)
- **Source**: manualCollection and from numerous dataset mentioned in academic papers
- **Features**: 38 features (36 lexical + 2 host-based)

### Test Dataset
- **Source**: manualCollection and from academic mentioned datasets

#### Test Set 1: Benign-focused Test
- **Size**: 77 URLs (all benign)
- **Purpose**: Benign model performance evaluation

#### Test Set 2: Mixed Classification Test  
- **Size**: 675 URLs
  - 123 benign URLs
  - 552 malicious URLs
- **Purpose**: Overall model performance evaluation

## Model Performance Comparison

| Model Version | Training Accuracy | Test Set 1 (77 Benign) | Test Set 2 (675 Mixed) |
|---------------|-------------------|-------------------------|-------------------------|
| **Model 1st** | 98.00% | 66 benign, 11 misclassified | 657 correct (534 malicious + 123 benign) |
| **Model 2nd** | 98.67% | 58 benign, 19 misclassified | 662 correct (539 malicious + 123 benign) |
| **Model 3rd** ⭐ | **98.83%** | 68 benign, 9 misclassified | 669 correct (546 malicious + 123 benign) |

## Model Evolution

### Model 1st
- **Training Accuracy**: 98.00%
- **Test Set 1 Performance**: 66/77 benign correctly classified (85.7% benign precision)
- **Test Set 2 Performance**: 534/552 malicious detected (96.7% malicious recall)

### Model 2nd
- **Training Accuracy**: 98.67%
- **Test Set 1 Performance**: 58/77 benign correctly classified (75.3% benign precision)
- **Test Set 2 Performance**: 539/552 malicious detected (97.6% malicious recall)

### Model 3rd (Current)
- **Training Accuracy**: 98.83%
- **Test Set 1 Performance**: 68/77 benign correctly classified (88.3% benign precision)
- **Test Set 2 Performance**: 546/552 malicious detected (98.9% malicious recall)

## Key Performance Metrics

### Current Model (3rd) Strengths:
- **High Training Accuracy**: 98.83%
- **Excellent Malicious Detection**: 98.9% recall on test set
- **Balanced Performance**: Good performance on both benign and malicious URLs
- **Progressive Improvement**: Each model iteration showed improved training accuracy

### Model Architecture:
- **Algorithm**: XGBoost Classifier
- **Feature Set**: 38 carefully engineered features
- **Training Approach**: Balanced datasets (50% benign, 50% malicious)
- **Final Training Data**: 6,000 URLs (3,000 benign + 3,000 malicious)
- **File Format**: Serialized as .json using joblib

## Feature Engineering

The model analyzes 38 features extracted from URLs:

### Lexical Features (36)
- URL structure analysis
- Character pattern recognition  
- String composition metrics
- Domain and path characteristics

### Host-based Features (2)
- Domain registration information
- Domain expiration data

For detailed feature documentation, see [FEATURES.md](FEATURES.md).

## Retraining Information

The model underwent a systematic retraining process with progressively larger balanced datasets:

### Training Process:
1. **1st Model**: Initial training with 3,000 URLs (1,500 benign + 1,500 malicious)
   - **Performance**: 98.00% accuracy
   - **Dataset**: Balanced 50/50 split

2. **2nd Model**: Retrained with new 3,000 URLs (1,500 benign + 1,500 malicious) 
   - **Performance**: 98.67% accuracy (0.67% improvement)
   - **Dataset**: Fresh balanced 50/50 split
   - **Approach**: Same size, different data for robustness

3. **3rd Model**: Expanded training with 6,000 URLs (3,000 benign + 3,000 malicious)
   - **Performance**: 98.83% accuracy (0.16% improvement)
   - **Dataset**: Doubled dataset size, maintained 50/50 balance
   - **Approach**: Larger dataset for better generalization

### Key Training Principles:
- **Balanced Datasets**: All models trained with equal benign/malicious samples
- **Progressive Scaling**: 3k → 3k → 6k URL progression  
- **Consistent Improvement**: Each iteration achieved higher accuracy
- **Data Variety**: Model 2nd used fresh data, Model 3rd used larger fresh dataset

---

*Last Updated: August 2025*
*Model Version: 3rd (Current Production Model)*
