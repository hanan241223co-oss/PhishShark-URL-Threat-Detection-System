from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import re
import os
4
app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'model', 'url_model.pkl')

print(f"Loading model from: {MODEL_PATH}")
model = joblib.load(MODEL_PATH)
print("✅ Model loaded successfully!")

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


def sanity_check(url, prediction, probabilities):
    url_lower = url.lower()
    confidence = max(probabilities)

    trusted_domains = [
        'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
        'twitter.com', 'x.com', 'wikipedia.org', 'github.com',
        'microsoft.com', 'apple.com', 'amazon.com', 'linkedin.com',
        'reddit.com', 'netflix.com', 'zoom.us', 'stackoverflow.com',
        'whatsapp.com', 'gmail.com', 'outlook.com', 'yahoo.com',
        'bbc.com', 'cnn.com', 'nytimes.com', 'forbes.com',
        'flipkart.com', 'myntra.com', 'paytm.com', 'naukri.com'
    ]

    for domain in trusted_domains:
        if domain in url_lower:
            return 0

    has_ip = bool(re.compile(r'(\d{1,3}\.){3}\d{1,3}').search(url))
    has_at = '@' in url
    has_https = url.startswith('https')
    num_hyphens = url.count('-')
    url_length = len(url)

    strong_malicious_words = [
        'login', 'verify', 'secure', 'account', 'update', 'banking',
        'password', 'confirm', 'paypal', 'ebay', 'signin', 'validate',
        'free', 'lucky', 'prize', 'winner', 'urgent', 'suspended'
    ]
    matched_words = [w for w in strong_malicious_words if w in url_lower]

    red_flags = sum([
        has_ip,
        has_at,
        not has_https,
        num_hyphens > 2,
        url_length > 60,
        len(matched_words) >= 2,
        len(matched_words) >= 1,
    ])

    if prediction == 2 and red_flags >= 3:
        return 2

    if prediction == 2 and confidence < 0.70 and red_flags < 3:
        return 1

    is_clean = (
        has_https and
        not has_ip and
        not has_at and
        len(matched_words) == 0 and
        num_hyphens <= 1 and
        url_length < 60
    )

    if is_clean and prediction == 2:
        return 1

    return prediction


def generate_explanation(url, prediction):
    url_lower = url.lower()
    warnings = []
    attack_type = ""
    advice = []

    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    if ip_pattern.search(url):
        warnings.append(
            "🔴 This URL uses an IP address (numbers) instead of a website name. "
            "Attackers hide fake websites behind IP addresses because it is harder to trace them."
        )
        attack_type = "Malware Distribution or Phishing"

    if '@' in url:
        warnings.append(
            "🔴 The URL contains the '@' symbol. "
            "Hackers use this trick: 'http://google.com@evil.com' — your browser actually goes to evil.com, not Google!"
        )
        attack_type = "URL Spoofing Attack"

    suspicious_words_found = []
    phishing_words = ['login', 'verify', 'secure', 'account', 'update',
                      'banking', 'password', 'confirm', 'signin', 'validate']
    for word in phishing_words:
        if word in url_lower:
            suspicious_words_found.append(word)

    if suspicious_words_found:
        warnings.append(
            f"🟡 The URL contains suspicious words: {', '.join(suspicious_words_found)}. "
            "Attackers use these words to make fake websites look like real banks or social media sites."
        )
        attack_type = "Phishing Attack"

    if len(url) > 75:
        warnings.append(
            f"🟡 This URL is very long ({len(url)} characters). "
            "Attackers make URLs extra long to hide the real malicious part at the end."
        )

    if url.count('-') > 3:
        warnings.append(
            f"🟡 The URL has {url.count('-')} hyphens (-). "
            "Fake sites often use hyphens to look like real sites: 'paypal-secure-login-now.com'."
        )
        attack_type = "Phishing Attack (Brand Impersonation)"

    try:
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]
        parts = domain.split('.')
        if len(parts) > 4:
            warnings.append(
                f"🟡 The URL has many subdomain levels: {domain}. "
                "Attackers use deep subdomains to confuse users and hide the real domain at the end."
            )
    except:
        pass

    if not url.startswith('https'):
        warnings.append(
            "🟡 This URL does not use HTTPS (it is not encrypted). "
            "Safe websites use 'https://' — the 's' means your connection is private and protected."
        )

    scam_words = ['free', 'lucky', 'prize', 'winner', 'congratulations', 'click here', 'urgent']
    for word in scam_words:
        if word in url_lower:
            warnings.append(
                f"🔴 The URL contains the word '{word}'. "
                "This is a classic sign of a scam website trying to trick you with fake rewards."
            )
            attack_type = "Online Scam / Social Engineering"

    if prediction == 2:
        advice = [
            "🚫 Do NOT open this link under any circumstances.",
            "🚫 Do NOT enter your username, password, or any personal information.",
            "🚫 Do NOT download any files from this website.",
            "🚫 If you accidentally opened it, close the browser tab immediately.",
            "✅ Run an antivirus scan on your device.",
            "✅ Report this URL to Google Safe Browsing: safebrowsing.google.com"
        ]
    elif prediction == 1:
        advice = [
            "⚠️ Be very careful before opening this link.",
            "⚠️ Do NOT enter personal information or passwords.",
            "✅ Double-check the URL — look for spelling mistakes in the domain name.",
            "✅ If you need to log in somewhere, go directly to the official website by typing it yourself.",
            "✅ Ask a trusted adult or teacher before proceeding."
        ]
    else:
        advice = [
            "✅ This URL appears to be safe.",
            "✅ Always stay alert even on safe websites.",
            "✅ Never share passwords with anyone."
        ]

    attack_descriptions = {
        "Phishing Attack": (
            "A Phishing Attack is when hackers create a FAKE copy of a real website "
            "(like your bank or Gmail) to trick you into entering your password. "
            "They steal your login details and then access your real accounts."
        ),
        "Malware Distribution or Phishing": (
            "This URL might distribute Malware — harmful software that can infect your device. "
            "It can steal your files, spy on you through your camera, or lock your computer and demand money."
        ),
        "URL Spoofing Attack": (
            "URL Spoofing is when a link LOOKS like it goes to a safe website, "
            "but actually takes you somewhere dangerous. It's like a disguise for a dangerous link."
        ),
        "Phishing Attack (Brand Impersonation)": (
            "This website pretends to be a well-known company (like PayPal, Amazon, or your bank). "
            "It's completely FAKE and designed to steal your login credentials or payment information."
        ),
        "Online Scam / Social Engineering": (
            "This is a Scam website that uses excitement (free prizes, urgent warnings) "
            "to manipulate you into clicking or submitting personal data. There is NO real prize — "
            "they only want your personal information or to install harmful software."
        )
    }

    attack_description = attack_descriptions.get(
        attack_type,
        "This URL shows multiple suspicious characteristics that are commonly used in cyber attacks."
    )

    return {
        "warnings": warnings,
        "attack_type": attack_type if attack_type else "General Suspicious Activity",
        "attack_description": attack_description,
        "advice": advice
    }


@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'Please provide a URL'}), 400

        if len(url) < 4:
            return jsonify({'error': 'URL is too short'}), 400

        features = extract_features(url)
        features_array = np.array([features])

        prediction = model.predict(features_array)[0]
        probabilities = model.predict_proba(features_array)[0]
        confidence = round(max(probabilities) * 100, 1)

        prediction = sanity_check(url, prediction, probabilities)

        label_map = {0: 'Safe', 1: 'Suspicious', 2: 'Malicious'}
        label = label_map.get(prediction, 'Unknown')

        explanation = generate_explanation(url, prediction)

        return jsonify({
            'url': url,
            'prediction': int(prediction),
            'label': label,
            'confidence': confidence,
            'warnings': explanation['warnings'],
            'attack_type': explanation['attack_type'],
            'attack_description': explanation['attack_description'],
            'advice': explanation['advice']
        })

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'running', 'message': 'URL Detector is active!'})


if __name__ == '__main__':
    print("\n🚀 Starting Malicious URL Detector Server...")
    print("📡 Server running at: http://localhost:5000")
    print("Press Ctrl+C to stop the server\n")
    app.run(debug=True, port=5000)