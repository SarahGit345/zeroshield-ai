# XAI deletion test (amendment 9, part C)

Amendment 9 part C. Top-k = features named by the stored occlusion explanation, reset together.
Score removed = (original - after reset) / original, mean over flagged alerts; random = mean of 20 seeded draws per alert; bottom = the k features with the lowest occlusion contribution.

## S10 (3010 flagged alerts; recomputed vs stored score max difference 1.56e-02)

| k | top-k removed [95% CI] | random k removed [95% CI] | bottom k removed | top minus random [95% CI] | alerts below threshold after top-k |
|---|---|---|---|---|---|
| 1 | 71.8% [71.0%, 72.7%] | -107.7% [-112.9%, -103.1%] | -1780.3% | +179.6% [+174.9%, +184.2%] | 78.6% |
| 3 | -39.4% [-49.3%, -30.0%] | -391.9% [-405.7%, -378.4%] | -7254.9% | +352.6% [+334.3%, +370.3%] | 37.5% |
| 5 | -202.0% [-221.7%, -183.6%] | -761.7% [-785.7%, -738.5%] | -10830.4% | +559.7% [+529.0%, +592.0%] | 26.0% |

Top-3 removed per family: Benign -43.9%; Brute Force 7.8%; DDoS 39.5%; DoS 38.8%; Mirai 19.7%; Recon -7.3%; Spoofing -52.9%; Web-Based -36.5%

## S30 (1003 flagged alerts; recomputed vs stored score max difference 1.17e-02)

| k | top-k removed [95% CI] | random k removed [95% CI] | bottom k removed | top minus random [95% CI] | alerts below threshold after top-k |
|---|---|---|---|---|---|
| 1 | 69.3% [67.6%, 70.7%] | -101.0% [-110.6%, -92.6%] | -1607.7% | +170.2% [+161.8%, +178.8%] | 69.2% |
| 3 | -13.7% [-26.7%, -1.4%] | -348.6% [-374.3%, -324.5%] | -6194.0% | +334.8% [+305.4%, +365.4%] | 34.5% |
| 5 | -152.3% [-181.7%, -123.7%] | -665.2% [-710.6%, -622.8%] | -9211.7% | +512.8% [+461.9%, +567.1%] | 22.7% |

Top-3 removed per family: Benign -21.0%; Brute Force -21.0%; DDoS 47.9%; DoS 34.3%; Mirai 15.4%; Recon 15.5%; Spoofing -54.1%; Web-Based -15.8%

## S58 (exploratory) (720 flagged alerts; recomputed vs stored score max difference 2.44e-03)

| k | top-k removed [95% CI] | random k removed [95% CI] | bottom k removed | top minus random [95% CI] | alerts below threshold after top-k |
|---|---|---|---|---|---|
| 1 | 67.0% [64.9%, 68.9%] | -81.3% [-90.9%, -72.0%] | -1359.7% | +148.3% [+138.2%, +158.6%] | 59.7% |
| 3 | -13.2% [-26.7%, -1.4%] | -281.2% [-307.1%, -255.2%] | -5009.6% | +268.0% [+239.5%, +296.7%] | 27.9% |
| 5 | -142.1% [-172.8%, -112.9%] | -544.8% [-593.3%, -498.9%] | -7275.9% | +402.7% [+346.8%, +458.0%] | 18.3% |

Top-3 removed per family: Benign -34.7%; Brute Force -5.1%; DDoS 48.8%; DoS 44.5%; Mirai 16.9%; Recon 4.0%; Spoofing -26.4%; Web-Based -67.4%

