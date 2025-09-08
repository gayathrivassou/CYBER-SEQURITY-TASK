# password_strength_analyzer.py

import math
import string
try:
    from zxcvbn import zxcvbn
    HAS_ZXCVBN = True
except ImportError:
    HAS_ZXCVBN = False


def estimate_entropy(password: str) -> float:
    """Estimate password entropy in bits based on character pool and length."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    if pool == 0:
        return 0.0
    return math.log2(pool) * len(password)


def analyze_password(password: str):
    print("=" * 40)
    print(f"Analyzing password: {password}")
    print("=" * 40)

    # Entropy-based estimate
    entropy = estimate_entropy(password)
    print(f"Estimated entropy: {entropy:.2f} bits")

    # zxcvbn analysis (if installed)
    if HAS_ZXCVBN:
        results = zxcvbn(password)
        print(f"zxcvbn score (0–4): {results['score']}")
        print("Feedback:")
        fb = results["feedback"]
        if fb["warning"]:
            print(" - Warning:", fb["warning"])
        if fb["suggestions"]:
            for s in fb["suggestions"]:
                print(" - Suggestion:", s)
        print("Estimated crack times:")
        for k, v in results["crack_times_display"].items():
            print(f" - {k}: {v}")
    else:
        print("⚠️ zxcvbn not installed. Run `pip install zxcvbn` for detailed analysis.")

    print("=" * 40)


if __name__ == "__main__":
    # Example usage
    pwd = input("Enter a password to analyze: ")
    analyze_password(pwd)
