# LLM verification measurement (smoke)

Model `qwen3:8b` (digest 500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41, Ollama 0.40.15); temperature 0, seed 20261108. Stream `D:\B-Tech\Sem-7\Final year project\zeroshield-ai\backend\experiments\replay_streams\replay_stream_share30_seed3.jsonl` (SHA-256 1fb74980c8574b1c9df66eea6f8a911534cd19c2dbd2060758242a4320665e13). 10 of 10 alerts completed; mean 178 s per alert.

| verdict | count | share |
|---|---|---|
| VERIFIED | 10 | 100.0% |
| UNCERTAIN | 0 | 0.0% |
| REJECTED | 0 | 0.0% |
| LLM_FAILED | 0 | 0.0% |
| TIMEOUT | 0 | 0.0% |

| family | VERIFIED | UNCERTAIN | REJECTED | LLM_FAILED | TIMEOUT |
|---|---|---|---|---|---|
| Benign | 3 | 0 | 0 | 0 | 0 |
| Brute Force | 1 | 0 | 0 | 0 | 0 |
| DDoS | 1 | 0 | 0 | 0 | 0 |
| DoS | 1 | 0 | 0 | 0 | 0 |
| Mirai | 1 | 0 | 0 | 0 | 0 |
| Recon | 1 | 0 | 0 | 0 | 0 |
| Spoofing | 1 | 0 | 0 | 0 | 0 |
| Web-Based | 1 | 0 | 0 | 0 | 0 |

Failed checks (alerts failing each check):


Parsing: 10 valid on the first attempt; 0 invalid on the first attempt (0 fixed by the retry, 0 still invalid after it); 0 repaired without a retry; 0 replies hit the output cap; 0 timed out.
Time: mean 178 s per alert, max 211 s; mean 323 output tokens per attempt.
Template reasoning on the same alerts: {'VERIFIED': 10}.

False positives and the verification gate:

- Without the gate: 3 of 3 flagged benign alerts reach the automated policy.
- With the gate: 3 of 3 (benign VERIFIED rate 100.0%, 95% Wilson [43.8%, 100.0%]); reduction 0.0%.
- Cost: 7 of 7 attacks still reach the automated policy (attack VERIFIED rate 100.0%, 95% Wilson [64.6%, 100.0%]); the rest go to human review.

Verification checks faithfulness to the evidence, not whether the flow is an attack.
