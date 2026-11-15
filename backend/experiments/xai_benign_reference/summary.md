# Benign-reference occlusion (amendment 14, descriptive)

Reference: per-feature median of 878,328 train benign rows. Reset value = that median.

**Pre-stated reading — faithful beyond the top feature: NO.**

## S10 (3010 flagged alerts)

| k | top-k removed [95% CI] | random k removed | bottom k removed | top minus random [95% CI] | below threshold after top-k |
|---|---|---|---|---|---|
| 1 | 73.4% [72.5%, 74.2%] | -113.3% | -2950.7% | +186.7% [+180.0%, +193.3%] | 79.7% |
| 3 | -12.2% [-22.9%, -2.6%] | -370.0% | -6158.6% | +357.7% [+338.1%, +376.8%] | 45.6% |
| 5 | -103.6% [-121.5%, -86.5%] | -654.1% | -5998.7% | +550.6% [+519.2%, +581.9%] | 37.0% |

## S30 (1003 flagged alerts)

| k | top-k removed [95% CI] | random k removed | bottom k removed | top minus random [95% CI] | below threshold after top-k |
|---|---|---|---|---|---|
| 1 | 72.4% [70.9%, 73.8%] | -106.6% | -2659.6% | +178.9% [+166.5%, +191.6%] | 68.6% |
| 3 | -6.2% [-24.8%, 10.7%] | -332.6% | -5140.6% | +326.5% [+292.9%, +358.8%] | 44.6% |
| 5 | -84.7% [-114.5%, -56.1%] | -577.9% | -5113.3% | +493.2% [+441.4%, +543.0%] | 36.6% |

## S58 (exploratory) (720 flagged alerts)

| k | top-k removed [95% CI] | random k removed | bottom k removed | top minus random [95% CI] | below threshold after top-k |
|---|---|---|---|---|---|
| 1 | 72.0% [70.3%, 73.7%] | -78.6% | -2185.4% | +150.7% [+139.3%, +163.8%] | 59.2% |
| 3 | 13.7% [3.2%, 22.9%] | -249.5% | -4191.8% | +263.2% [+232.2%, +296.3%] | 35.6% |
| 5 | -56.7% [-85.6%, -31.5%] | -440.8% | -4019.3% | +384.1% [+335.5%, +432.2%] | 28.6% |

## Agreement with SHAP (same 296 S30 alerts as amendment 9)

| subset | alerts | top-1 zero ref | top-1 median ref | top-5 zero ref | top-5 median ref |
|---|---|---|---|---|---|
| Overall | 296 | 8.4% | 15.5% | 26.0% | 35.9% |
| Benign | 37 | 13.5% | 8.1% | 26.5% | 22.2% |
| Brute Force | 37 | 13.5% | 13.5% | 31.4% | 24.3% |
| DDoS | 37 | 8.1% | 32.4% | 34.6% | 61.1% |
| DoS | 37 | 2.7% | 24.3% | 25.9% | 70.8% |
| Mirai | 37 | 0.0% | 10.8% | 4.9% | 21.1% |
| Recon | 37 | 18.9% | 27.0% | 33.5% | 43.8% |
| Spoofing | 37 | 5.4% | 2.7% | 26.5% | 21.1% |
| Web-Based | 37 | 5.4% | 5.4% | 24.9% | 22.7% |
