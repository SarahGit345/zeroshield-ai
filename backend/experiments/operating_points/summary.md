# Detector operating points per family (amendment 13, descriptive)

Thresholds from 878,328 train benign scores; evaluated on 45,808,251 rows (0 non-finite skipped). No threshold is selected; the deployed threshold stays 0.0614.

| threshold | value | validation benign FPR | overall attack recall (row-weighted) |
|---|---|---|---|
| p90 | 0.0330 | 9.99% | 99.02% |
| p93 | 0.0461 | 6.93% | 98.90% |
| deployed | 0.0614 | 5.00% | 98.81% |
| p95 | 0.0614 | 5.00% | 98.81% |
| p97 | 0.0943 | 2.99% | 98.69% |
| p99 | 0.2425 | 0.98% | 98.31% |

Recall per family (flagged / rows); 95% Wilson interval for the deployed threshold.

| source/family | rows | p90 | p93 | deployed | p95 | p97 | p99 |
|---|---|---|---|---|---|---|---|
| validation/Benign | 219,867 | 10.0% | 6.9% | 5.0% [4.9, 5.1] | 5.0% | 3.0% | 1.0% |
| validation/Brute Force | 13,064 | 35.5% | 26.7% | 20.8% [20.1, 21.5] | 20.8% | 14.9% | 7.2% |
| validation/DDoS | 33,984,560 | 100.0% | 100.0% | 100.0% [100.0, 100.0] | 100.0% | 100.0% | 99.9% |
| validation/DoS | 8,090,738 | 100.0% | 100.0% | 100.0% [100.0, 100.0] | 100.0% | 100.0% | 99.6% |
| validation/Recon | 354,565 | 66.0% | 60.7% | 56.6% [56.4, 56.8] | 56.6% | 51.0% | 42.5% |
| validation/Spoofing | 486,504 | 37.3% | 30.9% | 25.7% [25.6, 25.9] | 25.7% | 19.7% | 8.2% |
| zero_day/Mirai | 2,634,124 | 100.0% | 100.0% | 100.0% [100.0, 100.0] | 100.0% | 100.0% | 99.3% |
| zero_day/Web-Based | 24,829 | 47.9% | 39.8% | 33.9% [33.3, 34.5] | 33.9% | 26.0% | 13.1% |
