# Amendment 12 one-time test on S10b (original snapshot)

Frozen guarded variant: `g1-scan-only`. Stream SHA-256: `93fe6dab564504cdf4e49adb8345bbe660432d83b6081f57c3a1043d1ef0aa18`.
Data basis: Original snapshot (validation 43,149,298 rows; zero-day 2,658,953 rows), see amendment 12.

| Method | DDoS | DoS | Recon | Brute Force | Spoofing | Mirai | Benign clean | Primary score | Precision | Mean candidates |
|---|---|---|---|---|---|---|---|---|---|---|
| TF-IDF only | 29/43 67.4% [52.5%, 79.5%] | 7/43 16.3% [8.1%, 30.0%] | 0/43 0.0% [0.0%, 8.2%] | 13/43 30.2% [18.6%, 45.1%] | 0/43 0.0% [0.0%, 8.2%] | 28/43 65.1% [50.2%, 77.6%] | 408/2709 15.1% [13.8%, 16.5%] | 0.2245 | 22.4% | 2.53 |
| TF-IDF + v2 filter | 29/43 67.4% [52.5%, 79.5%] | 7/43 16.3% [8.1%, 30.0%] | 0/43 0.0% [0.0%, 8.2%] | 8/43 18.6% [9.7%, 32.6%] | 0/43 0.0% [0.0%, 8.2%] | 28/43 65.1% [50.2%, 77.6%] | 735/2709 27.1% [25.5%, 28.8%] | 0.2752 | 38.9% | 1.51 |
| TF-IDF + mapping + v2 filter | 29/43 67.4% [52.5%, 79.5%] | 8/43 18.6% [9.7%, 32.6%] | 15/43 34.9% [22.4%, 49.8%] | 16/43 37.2% [24.4%, 52.1%] | 0/43 0.0% [0.0%, 8.2%] | 31/43 72.1% [57.3%, 83.3%] | 437/2709 16.1% [14.8%, 17.6%] | 0.2725 | 43.1% | 3.02 |
| TF-IDF + guarded mapping + v2 filter | 29/43 67.4% [52.5%, 79.5%] | 7/43 16.3% [8.1%, 30.0%] | 17/43 39.5% [26.4%, 54.4%] | 8/43 18.6% [9.7%, 32.6%] | 0/43 0.0% [0.0%, 8.2%] | 28/43 65.1% [50.2%, 77.6%] | 726/2709 26.8% [25.2%, 28.5%] | 0.3065 | 40.5% | 1.91 |

**Guarded mapping minus TF-IDF + v2 filter: +0.0313, 95% paired bootstrap [+0.0191, +0.0433]. Verdict: SUCCESS.**
Replication of the amendment 7 map on this snapshot: -0.0027 [-0.0198, +0.0167].
Web-Based alerts (out of scope): 43.
Run once. Labels used only after retrieval, to score relevance.
