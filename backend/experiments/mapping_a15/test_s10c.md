# Amendment 15 one-time test on S10c (original snapshot)

Frozen gate: `gate-3x` on guarded mapping `g1-scan-only`. Stream SHA-256: `97d0411bcd10f4f724ec8d8c91943d927ad8f212196eac2276b9cc5cb86531c5`.

| Method | DDoS | DoS | Recon | Brute Force | Spoofing | Mirai | Benign clean | Primary score | Precision | Mean candidates |
|---|---|---|---|---|---|---|---|---|---|---|
| TF-IDF only | 21/43 48.8% [34.6%, 63.2%] | 9/43 20.9% [11.4%, 35.2%] | 0/43 0.0% [0.0%, 8.2%] | 15/43 34.9% [22.4%, 49.8%] | 0/43 0.0% [0.0%, 8.2%] | 29/43 67.4% [52.5%, 79.5%] | 423/2709 15.6% [14.3%, 17.0%] | 0.2215 | 21.9% | 2.53 |
| TF-IDF + v2 filter | 21/43 48.8% [34.6%, 63.2%] | 9/43 20.9% [11.4%, 35.2%] | 0/43 0.0% [0.0%, 8.2%] | 9/43 20.9% [11.4%, 35.2%] | 0/43 0.0% [0.0%, 8.2%] | 29/43 67.4% [52.5%, 79.5%] | 765/2709 28.2% [26.6%, 30.0%] | 0.2730 | 40.9% | 1.52 |
| TF-IDF + guarded mapping + v2 filter | 21/43 48.8% [34.6%, 63.2%] | 9/43 20.9% [11.4%, 35.2%] | 17/43 39.5% [26.4%, 54.4%] | 9/43 20.9% [11.4%, 35.2%] | 0/43 0.0% [0.0%, 8.2%] | 29/43 67.4% [52.5%, 79.5%] | 760/2709 28.1% [26.4%, 29.8%] | 0.3050 | 43.0% | 1.89 |
| TF-IDF + guarded mapping + v2 filter + score gate | 21/43 48.8% [34.6%, 63.2%] | 9/43 20.9% [11.4%, 35.2%] | 16/43 37.2% [24.4%, 52.1%] | 0/43 0.0% [0.0%, 8.2%] | 0/43 0.0% [0.0%, 8.2%] | 29/43 67.4% [52.5%, 79.5%] | 2141/2709 79.0% [77.5%, 80.5%] | 0.5405 | 49.8% | 0.60 |

**Gated minus guarded mapping: +0.2355, 95% paired bootstrap [+0.2208, +0.2489]. Verdict: SUCCESS.**
Attack alerts that lose all context because of the gate: Brute Force 57%; DDoS 0%; DoS 0%; Mirai 0%; Recon 12%; Spoofing 67%; Web-Based 43%.
Run once. Labels used only after retrieval, to score relevance.
