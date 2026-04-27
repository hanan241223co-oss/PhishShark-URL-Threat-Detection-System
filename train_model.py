import pandas as pd
import numpy as np
import re
import joblib
import os

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder


def extract_features(url):
    features = {}

    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['has_https'] = 1 if url.startswith('https') else 0

    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    features['has_ip'] = 1 if ip_pattern.search(url) else 0

    special_chars = re.findall(r'[!@#$%^&*()_+=\[\]{};:\'",<>?/\\|`~]', url)
    features['num_special_chars'] = len(special_chars)

    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')

    suspicious_words = [
        'login', 'verify', 'secure', 'account', 'update',
        'banking', 'password', 'confirm', 'paypal', 'ebay',
        'signin', 'free', 'lucky', 'prize', 'click', 'here',
        'urgent', 'suspended', 'unusual', 'activity', 'validate'
    ]
    url_lower = url.lower()
    features['has_suspicious_words'] = sum(
        1 for word in suspicious_words if word in url_lower
    )

    try:
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]
        features['domain_length'] = len(domain)
    except:
        features['domain_length'] = len(url)

    try:
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]
        domain_parts = domain.split('.')
        features['num_subdomains'] = max(0, len(domain_parts) - 2)
    except:
        features['num_subdomains'] = 0

    try:
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]
        features['digits_in_domain'] = sum(c.isdigit() for c in domain)
    except:
        features['digits_in_domain'] = 0

    return list(features.values())


print("📂 Loading dataset...")

df = pd.read_csv('dataset/urls.csv')

print(f"Dataset loaded! Total URLs: {len(df)}")
print(df.head())
print(f"\nColumn names: {df.columns.tolist()}")

if 'URL' in df.columns:
    df.rename(columns={'URL': 'url'}, inplace=True)
if 'type' in df.columns:
    df.rename(columns={'type': 'label'}, inplace=True)
if 'category' in df.columns:
    df.rename(columns={'category': 'label'}, inplace=True)

print(f"\nUnique labels found: {df['label'].unique()}")


def categorize_label(label):
    label = str(label).lower().strip()
    if label in ['benign', 'safe', '0']:
        return 0
    elif label in ['phishing', 'suspicious', 'spam']:
        return 1
    else:
        return 2

df['label_num'] = df['label'].apply(categorize_label)

print("\nLabel distribution:")
print(df['label_num'].value_counts())
print("0=Safe, 1=Suspicious, 2=Malicious")


print("\n⚙️  Extracting features from URLs (this may take a few minutes)...")

df = df.head(150000)

X = np.array([extract_features(url) for url in df['url']])
y = df['label_num'].values

print(f"Feature extraction complete! Shape: {X.shape}")


X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42
)

print(f"\nTraining samples: {len(X_train)}")
print(f"Testing samples:  {len(X_test)}")


print("\n🤖 Training the Random Forest model...")

model = RandomForestClassifier(
    n_estimators=200,        
    random_state=42,
    n_jobs=-1,
    class_weight='balanced', 
    min_samples_leaf=2,
    max_features='sqrt'
)

model.fit(X_train, y_train)

print("✅ Training complete!")


print("\n📊 Evaluating model performance...")

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"\n🎯 Model Accuracy: {accuracy * 100:.2f}%")

print("\nDetailed Classification Report:")
print(classification_report(
    y_test, y_pred,
    target_names=['Safe', 'Suspicious', 'Malicious']
))


os.makedirs('model', exist_ok=True)

joblib.dump(model, 'model/url_model.pkl')

print("\n💾 Model saved to: model/url_model.pkl")
print("\n🚀 You can now run the Flask backend!")