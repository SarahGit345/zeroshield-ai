# Occlusion vs SHAP (amendment 9, part D)

Amendment 9 part D. shap.GradientExplainer on the detector score; background 200 unflagged benign alerts from S58. SHAP top-5 by value (pushes the score up) and by absolute value.

| subset | alerts | top-1 agreement | top-5 overlap (SHAP by value) | top-5 overlap (SHAP by abs value) |
|---|---|---|---|---|
| Overall | 296 | 10.1% | 26.4% | 21.6% |
| Benign | 37 | 13.5% | 28.1% | 23.8% |
| Brute Force | 37 | 16.2% | 31.9% | 29.7% |
| DDoS | 37 | 8.1% | 34.1% | 25.9% |
| DoS | 37 | 2.7% | 24.3% | 9.2% |
| Mirai | 37 | 0.0% | 6.5% | 2.7% |
| Recon | 37 | 29.7% | 34.6% | 34.1% |
| Spoofing | 37 | 5.4% | 25.4% | 23.2% |
| Web-Based | 37 | 5.4% | 26.5% | 24.3% |
