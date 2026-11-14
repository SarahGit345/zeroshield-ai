# Technique plausibility: retrieval abstention and verifier check (post hoc, amendment 5)

Rules `plausibility-rules-v1`. Run once. No LLM call; nothing tuned (the rules have no threshold).

## (a) Retrieval, 200-sample labelled evidence, detector-flagged

| subset | samples | answered | relevant | wrong answers | precision when answering |
|---|---|---|---|---|---|
| tuning half, flagged, abstention off | 47 | 29 | 18 | 11 | 0.621 |
| tuning half, flagged, abstention on | 47 | 10 | 5 | 5 | 0.5 |
| test half, flagged, abstention off | 53 | 37 | 19 | 18 | 0.514 |
| test half, flagged, abstention on | 53 | 13 | 3 | 10 | 0.231 |

Test half per family (off -> on): flagged / answered / relevant

- Backdoor_Malware: 5 / 3 -> 1 / 0 -> 0
- BrowserHijacking: 2 / 2 -> 2 / 0 -> 0
- CommandInjection: 4 / 1 -> 1 / 0 -> 0
- Mirai-greeth_flood: 10 / 10 -> 1 / 9 -> 1
- Mirai-greip_flood: 10 / 10 -> 1 / 9 -> 1
- Mirai-udpplain: 10 / 4 -> 1 / 1 -> 1
- SqlInjection: 6 / 3 -> 3 / 0 -> 0
- Uploading_Attack: 2 / 2 -> 2 / 0 -> 0
- XSS: 4 / 2 -> 1 / 0 -> 0

## (b) The 100 saved main-run reports

Candidates 198; removed as implausible 106; not judged (no rule) 0. Recomputed 11-check verdicts that differ from the saved ones: 0.

| family | alerts | with candidates before -> after | relevant candidate before -> after | VERIFIED 11 checks -> 12 | faithful-but-wrong before -> after | relevant-citing reports downgraded |
|---|---|---|---|---|---|---|
| Benign | 30 | 21 -> 19 | 0 -> 0 | 30 -> 22 | 21 -> 13 | 0 |
| Brute Force | 10 | 9 -> 8 | 5 -> 0 | 9 -> 4 | 3 -> 3 | 5 |
| DDoS | 10 | 6 -> 5 | 5 -> 4 | 9 -> 6 | 1 -> 0 | 2 |
| DoS | 10 | 3 -> 2 | 2 -> 2 | 10 -> 9 | 1 -> 0 | 0 |
| Mirai | 10 | 6 -> 2 | 6 -> 2 | 10 -> 6 | 1 -> 0 | 3 |
| Recon | 10 | 8 -> 6 | 0 -> 0 | 10 -> 4 | 8 -> 2 | 0 |
| Spoofing | 10 | 7 -> 6 | 0 -> 0 | 10 -> 7 | 7 -> 4 | 0 |
| Web-Based | 10 | 5 -> 5 | 0 -> 0 | 10 -> 9 | 5 -> 4 | 0 |
| Total | 100 | 65 -> 53 | 18 -> 8 | 98 -> 67 | 47 -> 26 | 10 |

Benign rows: VERIFIED is a false positive reaching the automated policy; 'relevant candidate' does not apply.

## (c) Damage test with the check on (reports still VERIFIED with it on)

| damage | caught | 95% CI |
|---|---|---|
| status contradicts detector | 67/67 | [94.6%, 100.0%] |
| below-threshold claim | 67/67 | [94.6%, 100.0%] |
| technique not retrieved | 67/67 | [94.6%, 100.0%] |
| fabricated number | 67/67 | [94.6%, 100.0%] |
| fake rounding of threshold | 39/67 | [46.3%, 69.3%] |
| wrong feature direction | 67/67 | [94.6%, 100.0%] |
| feature outside XAI evidence | 67/67 | [94.6%, 100.0%] |
| certainty overclaim | 67/67 | [94.6%, 100.0%] |
| completed-action claim | 67/67 | [94.6%, 100.0%] |
| invented IP | 67/67 | [94.6%, 100.0%] |
| invented MAC | 67/67 | [94.6%, 100.0%] |
| invented date | 67/67 | [94.6%, 100.0%] |
| invented URL | 67/67 | [94.6%, 100.0%] |
| limitations removed | 67/67 | [94.6%, 100.0%] |
