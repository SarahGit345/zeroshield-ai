# Amendment 7 one-time test on S10b

Evaluated once after the mapping freeze commit. Revised-data-basis replication under amendments 10-11; this is not the older source snapshot recorded in the original stream metadata.

Stream SHA-256: `bc579188c3d132264fddcf8eef13a95ab85498a6feb8aeaca216a10e406ca095`.

| Method | DDoS | DoS | Recon | Brute Force | Spoofing | Mirai | Benign clean | Primary balanced score | Precision (in-scope attack candidates) | Mean candidates / alert |
|---|---|---|---|---|---|---|---|---:|---:|---:|
| TF-IDF only | 27/43 62.8% [47.9%, 75.6%] | 10/43 23.3% [13.2%, 37.7%] | 0/43 0.0% [0.0%, 8.2%] | 15/43 34.9% [22.4%, 49.8%] | 0/43 0.0% [0.0%, 8.2%] | 27/43 62.8% [47.9%, 75.6%] | 417/2709 15.4% [14.1%, 16.8%] | 0.2301 | 23.4% | 2.51 |
| TF-IDF + v2 filter | 27/43 62.8% [47.9%, 75.6%] | 10/43 23.3% [13.2%, 37.7%] | 0/43 0.0% [0.0%, 8.2%] | 8/43 18.6% [9.7%, 32.6%] | 0/43 0.0% [0.0%, 8.2%] | 27/43 62.8% [47.9%, 75.6%] | 739/2709 27.3% [25.6%, 29.0%] | 0.2759 | 39.4% | 1.51 |
| TF-IDF + mapping + v2 filter | 27/43 62.8% [47.9%, 75.6%] | 11/43 25.6% [14.9%, 40.2%] | 17/43 39.5% [26.4%, 54.4%] | 14/43 32.6% [20.5%, 47.5%] | 1/43 2.3% [0.4%, 12.1%] | 28/43 65.1% [50.2%, 77.6%] | 415/2709 15.3% [14.0%, 16.7%] | 0.2665 | 42.5% | 3.03 |

**Verdict: no improvement over TF-IDF + v2 filter.** Mapping minus v2 primary score = -0.0094; 95% paired-bootstrap interval [-0.0264, +0.0086] (2,000 stratified paired resamples, seed 20261115). The interval includes zero, and the mapping primary score is lower.

Recon coverage: 17/43 (39.5%, [26.4%, 54.4%]).
Spoofing coverage: 1/43 (2.3%, [0.4%, 12.1%]).
Web-Based: 43 alerts, out of scope; flow features do not show HTTP content.

Labels were used only after retrieval to score relevance. Benign clean rate measures alerts with no candidate; precision counts candidate IDs on in-scope attack alerts. The mapping remains off by default.
