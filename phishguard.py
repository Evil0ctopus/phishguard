import re
import sys

# --- Keyword list (starter set, expandable later) ---
PHISHING_KEYWORDS = [
    "urgent", "verify", "account", "password", "click here",
    "limited time", "winner", "payment", "invoice", "login"
]

# --- Suspicious domains (starter set, expandable later) ---
SUSPICIOUS_DOMAINS = [
    "paypa1.com", "login-secure.net", "verify-account.org",
    "secure-update.com", "bank-login.net"
]

def check_keywords(email_text):
    """Scan email text for phishing keywords."""
    score = 0
    found = []
    for word in PHISHING_KEYWORDS:
        if word in email_text.lower():
            score += 1
            found.append(word)
    return score, found

def check_links(email_text):
    """Extract URLs and flag suspicious domains."""
    urls = re.findall(r'(https?://[^\s]+)', email_text)
    flagged = []
    for url in urls:
        for domain in SUSPICIOUS_DOMAINS:
            if domain in url.lower():
                flagged.append(url)
    return urls, flagged

def analyze_email(email_text):
    """Run phishing checks and return results."""
    keyword_score, keywords_found = check_keywords(email_text)
    urls, flagged_urls = check_links(email_text)

    print("=== PhishGuard Report ===")
    print(f"Phishing keyword score: {keyword_score}")
    if keywords_found:
        print("Keywords found:", ", ".join(keywords_found))
    else:
        print("No suspicious keywords detected.")

    if urls:
        print("Links detected:", ", ".join(urls))
    if flagged_urls:
        print("⚠️ Suspicious links flagged:", ", ".join(flagged_urls))
    else:
        print("No suspicious links flagged.")

    # Simple risk assessment
    risk = keyword_score + len(flagged_urls)
    if risk >= 3:
        print(">>> HIGH RISK: This email looks suspicious!")
    elif risk == 2:
        print(">>> MEDIUM RISK: Be cautious.")
    else:
        print(">>> LOW RISK: No major red flags detected.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python phishguard.py <email_file.txt>")
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        email_text = f.read()

    analyze_email(email_text)
