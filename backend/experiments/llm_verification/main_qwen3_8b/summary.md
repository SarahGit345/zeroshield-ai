# LLM verification measurement (main)

Model `qwen3:8b` (digest 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41, Ollama 0.40.15); temperature 0, seed 20261108. Stream `D:\B-Tech\Sem-7\Final year project\zeroshield-ai\backend\experiments\replay_streams\replay_stream_share30_seed3.jsonl` (SHA-256 1fb74980c8574b1c9df66eea6f8a911534cd19c2dbd2060758242a4320665e13). 100 of 100 alerts completed; mean 176 s per alert.

| verdict | count | share |
|---|---|---|
| VERIFIED | 98 | 98.0% |
| UNCERTAIN | 2 | 2.0% |
| REJECTED | 0 | 0.0% |
| LLM_FAILED | 0 | 0.0% |
| TIMEOUT | 0 | 0.0% |

| family | VERIFIED | UNCERTAIN | REJECTED | LLM_FAILED | TIMEOUT |
|---|---|---|---|---|---|
| Benign | 30 | 0 | 0 | 0 | 0 |
| Brute Force | 9 | 1 | 0 | 0 | 0 |
| DDoS | 9 | 1 | 0 | 0 | 0 |
| DoS | 10 | 0 | 0 | 0 | 0 |
| Mirai | 10 | 0 | 0 | 0 | 0 |
| Recon | 10 | 0 | 0 | 0 | 0 |
| Spoofing | 10 | 0 | 0 | 0 | 0 |
| Web-Based | 10 | 0 | 0 | 0 | 0 |

Failed checks (alerts failing each check):

- feature_directions_consistent: 2 (2.0%)

Parsing: 100 valid on the first attempt; 0 invalid on the first attempt (0 fixed by the retry, 0 still invalid after it); 0 repaired without a retry; 0 replies hit the output cap; 0 timed out.
Time: mean 176 s per alert, max 281 s; mean 315 output tokens per attempt.
Template reasoning on the same alerts: {'VERIFIED': 100}.

False positives and the verification gate:

- Without the gate: 30 of 30 flagged benign alerts reach the automated policy.
- With the gate: 30 of 30 (benign VERIFIED rate 100.0%, 95% Wilson [88.6%, 100.0%]); reduction 0.0%.
- Cost: 68 of 70 attacks still reach the automated policy (attack VERIFIED rate 97.1%, 95% Wilson [90.2%, 99.2%]); the rest go to human review.

Verification checks faithfulness to the evidence, not whether the flow is an attack.

Techniques cited (descriptive): attacks relevant 1, irrelevant 0, none 69; benign citing a technique 1 (unsupported), benign citing none 29; no report 0. Faithful but wrong (VERIFIED and irrelevant, or benign citing one): 1.

Human-check sample (30 reports, seed 20261108): see summary.json `human_check_sample`.
