import base64

def create_breach_monitoring_filter():
    # Comprehensive list of data breach keywords
    breach_keywords = [
        # Primary Data Breach Keywords
        "data breach",
        "data leak",
        "data exposure",
        "security breach",
        "cyber incident",
        "unauthorized access",
        "data theft",
        "information disclosure",
        "security incident",
        "data compromise",
        
        # Specific Breach Types
        "ransomware attack",
        "credential leak",
        "database exposed",
        "database leak",
        "PII exposed",
        "personal data leak",
        "customer data breach",
        "employee data breach",
        "medical records breach",
        "financial data breach",
        "password leak",
        "email leak",
        
        # Technical Indicators
        "misconfigured database",
        "unsecured database",
        "exposed S3 bucket",
        "exposed API",
        "MongoDB exposed",
        "Elasticsearch exposed",
        "Firebase exposed",
        "exposed credentials",
        "leaked database",
        "config file exposed",
        
        # Breach Actors/Sources
        "threat actor claims",
        "dark web leak",
        "breach forum",
        "BreachForums",
        "telegram leak",
        "hacktivist leak",
        "insider threat",
        "third-party breach",
        "supply chain breach",
        "vendor breach",
        
        # Regulatory/Disclosure Terms
        "breach notification",
        "GDPR breach",
        "HIPAA breach",
        "data incident",
        "security advisory",
        "breach disclosure",
        "incident response",
        "data protection violation",
        "regulatory fine",
        "class action breach",
        
        # Industry-Specific
        "healthcare breach",
        "hospital breach",
        "banking breach",
        "retail breach",
        "government breach",
        "education breach",
        "university breach",
        "insurance breach",
        "telecom breach",
        "SaaS breach",
        
        # Breach Impact Terms
        "million records",
        "affected users",
        "compromised accounts",
        "stolen data",
        "exfiltrated data",
        "data for sale",
        "leaked online",
        "publicly exposed",
        "breach confirmed",
        "investigating breach",
        
        # Additional High-Value Terms
        "zero-day exploit",
        "vulnerability exploited",
        "cyberattack",
        "data exfiltration",
        "security vulnerability",
        "compromised database",
        "breach database",
        "Have I Been Pwned",
        "Troy Hunt",
        "threat intelligence"
    ]
    
    # Build the search string
    search = ''
    for keyword in breach_keywords:
        search += ',{"text":"' + keyword + '"}'
    
    # Create the Feedly filter
    feedly_filter = '{"layers":[{"parts":[{"type":"customKeyword"'+search+'],"salience":"mention","searchHint":"","type":"matches"}],"bundles":[]}'
    
    # Remove the first comma and the 4th '{'
    count = 0
    removed = False
    new_feedly_filter = ''
    
    for char in feedly_filter:
        if char == '{':
            count += 1
        if count == 4 and not removed:
            removed = True
            continue
        new_feedly_filter += char
    
    # Base64 encode the filter
    encoded_filter = base64.b64encode(new_feedly_filter.encode()).decode()
    
    # Create the Feedly URL
    feedly_filter_url = f"https://feedly.com/i/powerSearch/in?options={encoded_filter}"
    
    print("\n*******************************")
    print("*  Data Breach Monitoring     *")
    print("*  Clear Text Feedly Filter   *")
    print("*******************************\n")
    print(new_feedly_filter)
    
    print("\n*******************************")
    print("*  Encoded Feedly Filter URL  *")
    print("*******************************\n")
    print(feedly_filter_url)
    
    print("\n*******************************")
    print("*  Total Keywords: {}        *".format(len(breach_keywords)))
    print("*******************************\n")
    
    return feedly_filter_url, new_feedly_filter

if __name__ == "__main__":
    create_breach_monitoring_filter()
