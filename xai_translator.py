"""
XAI Translator module.
Translates model features to human-readable explanations.
"""

FEATURE_LABELS = {
    "length": "Domain Length",
    "n_ns": "Name Server Count",
    "n_vowels": "Vowel Count",
    "life_time": "Domain Age",
    "n_vowel_chars": "Vowel Characters",
    "n_constant_chars": "Consonant Characters",
    "n_nums": "Numeric Characters",
    "n_other_chars": "Special Characters",
    "entropy": "Domain Entropy",
    "n_mx": "Mail Exchange Records",
    "ns_similarity": "Nameserver Similarity",
    "n_countries": "Hosting Countries",
    "n_labels": "HTML Element Count",
}

def translate(features: dict) -> list[dict]:
    explanations = []
    
    for feature, label in FEATURE_LABELS.items():
        if feature not in features:
            continue
            
        value = features[feature]
        
        if value is None:
            explanations.append({
                "feature": feature,
                "label": label,
                "value": value,
                "verdict": "Data unavailable",
                "severity": "neutral"
            })
            continue

        severity = "medium"
        verdict = ""
        
        if feature == "length":
            if value > 20:
                severity, verdict = "high", "Suspiciously long domain name"
            elif value <= 12:
                severity, verdict = "safe", "Standard domain length"
            else:
                severity, verdict = "medium", "Slightly longer than average domain length"
                
        elif feature == "n_ns":
            if value == 0:
                severity, verdict = "high", "No name servers found \u2014 highly unusual"
            elif value >= 3:
                severity, verdict = "safe", "Multiple name servers found (robust infrastructure)"
            else:
                severity, verdict = "medium", "Fewer name servers than typical enterprise domains"
                
        elif feature == "n_vowels":
            if value >= 5:
                severity, verdict = "high", "High number of vowels, common in automatically generated domains"
            elif value <= 3:
                severity, verdict = "safe", "Normal vowel count"
            else:
                severity, verdict = "medium", "Slightly elevated vowel count"
                
        elif feature == "life_time":
            if value <= 365:
                # The exact verdict from the prompt requirements
                severity, verdict = "high", "Suspiciously young \u2014 registered for only 1 year or less"
            elif value >= 2000:
                severity, verdict = "safe", "Well-established domain with long history"
            else:
                severity, verdict = "medium", "Moderate domain age"
                
        elif feature == "n_vowel_chars":
            if value >= 8:
                severity, verdict = "high", "Suspiciously high number of vowel characters"
            elif value <= 4:
                severity, verdict = "safe", "Normal number of vowel characters"
            else:
                severity, verdict = "medium", "Elevated number of vowel characters"
                
        elif feature == "n_constant_chars":
            if value >= 12:
                severity, verdict = "high", "Suspiciously high number of consonant characters"
            elif value <= 6:
                severity, verdict = "safe", "Normal number of consonant characters"
            else:
                severity, verdict = "medium", "Elevated number of consonant characters"
                
        elif feature == "n_nums":
            if value >= 2:
                severity, verdict = "high", "Multiple numeric characters found in domain name"
            elif value == 0:
                severity, verdict = "safe", "No numeric characters, typical for standard domains"
            else:
                severity, verdict = "medium", "Contains a numeric character"
                
        elif feature == "n_other_chars":
            if value >= 1:
                severity, verdict = "high", "Contains special characters \u2014 unusual for standard domains"
            elif value == 0:
                severity, verdict = "safe", "No special characters (standard)"
            else:
                severity, verdict = "medium", "May contain unusual characters"
                
        elif feature == "entropy":
            if value >= 3.8:
                severity, verdict = "high", "High entropy \u2014 domain looks random or machine-generated"
            elif value <= 2.8:
                severity, verdict = "safe", "Low entropy \u2014 domain looks like standard natural language"
            else:
                severity, verdict = "medium", "Moderate entropy \u2014 slightly complex domain string"
                
        elif feature == "n_mx":
            if value == 0:
                # The exact verdict from the prompt requirements
                severity, verdict = "high", "No mail records found \u2014 unusual for legitimate domains"
            elif value >= 2:
                severity, verdict = "safe", "Multiple mail servers configured"
            else:
                severity, verdict = "medium", "Fewer mail records than typical"
                
        elif feature == "ns_similarity":
            if value <= 0.5:
                severity, verdict = "high", "Low nameserver similarity \u2014 disjointed infrastructure"
            elif value >= 0.9:
                severity, verdict = "safe", "High nameserver similarity \u2014 expected infrastructure pattern"
            else:
                severity, verdict = "medium", "Moderate nameserver similarity"
                
        elif feature == "n_countries":
            if value >= 3:
                severity, verdict = "high", "Hosted across many countries \u2014 suspicious distribution"
            elif value == 1:
                severity, verdict = "safe", "Hosted in a single country \u2014 typical footprint"
            else:
                severity, verdict = "medium", "Hosted across a couple of countries"
                
        elif feature == "n_labels":
            if value == 0:
                severity, verdict = "high", "No HTML elements \u2014 page may be empty, blocked, or not serving standard content"
            elif value >= 200:
                severity, verdict = "safe", "Rich HTML content indicative of a real website"
            else:
                severity, verdict = "medium", "Low HTML element count \u2014 potentially simple or parked page"

        explanations.append({
            "feature": feature,
            "label": label,
            "value": value,
            "verdict": verdict,
            "severity": severity
        })

    # Sort explanations: high > medium > safe/neutral
    def severity_rank(item):
        ranks = {"high": 0, "medium": 1, "safe": 2, "neutral": 3}
        return ranks.get(item["severity"], 4)

    explanations.sort(key=severity_rank)
    
    return explanations

if __name__ == "__main__":
    # Profile 1 - Known malicious pattern (values from Table 10 of the MADONNA paper, e.g. chromnius.download)
    p1 = {
        "length": 18, "n_ns": 2, "n_vowels": 4, "life_time": 365, "n_vowel_chars": 6,
        "n_constant_chars": 12, "n_nums": 0, "n_other_chars": 0, "entropy": 3.68,
        "n_mx": 5, "ns_similarity": 1.0, "n_countries": 2, "n_labels": 276
    }
    out1 = translate(p1)
    high_count_1 = sum(1 for e in out1 if e["severity"] == "high")
    
    assert high_count_1 >= 2, f"Expected at least 2 high, got {high_count_1}"
    
    # Profile 2 - Known benign pattern (values from Table 8, e.g. google.com)
    p2 = {
        "length": 10, "n_ns": 4, "n_vowels": 2, "life_time": 11322, "n_vowel_chars": 4,
        "n_constant_chars": 5, "n_nums": 0, "n_other_chars": 0, "entropy": 2.64,
        "n_mx": 1, "ns_similarity": 0.93, "n_countries": 1, "n_labels": 353
    }
    out2 = translate(p2)
    high_count_2 = sum(1 for e in out2 if e["severity"] == "high")
    assert high_count_2 == 0, f"Expected 0 high, got {high_count_2}"
    
    # Profile 3 - Missing and None values
    p3 = {"length": None, "n_ns": 0}
    out3 = translate(p3)
    
    assert len(out3) == 2, f"Expected 2 explanations, got {len(out3)}"
    
    length_explanation = next((e for e in out3 if e["feature"] == "length"), None)
    n_ns_explanation = next((e for e in out3 if e["feature"] == "n_ns"), None)
    
    assert length_explanation is not None and length_explanation["severity"] == "neutral"
    assert n_ns_explanation is not None and n_ns_explanation["severity"] == "high"
    
    print("All tests passed.")
