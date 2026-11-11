Damage test on 98 VERIFIED main-run reports (one damage per report per kind).

| damage | expected check | caught | rate [95% CI] | by expected check |
|---|---|---|---|---|
| status contradicts detector | threshold_and_status | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |
| below-threshold claim | threshold_and_status | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |
| technique not retrieved | technique_ids_retrieved | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |
| fabricated number | numeric_claims_grounded | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |
| fake rounding of threshold | numeric_claims_grounded | 59/98 | 60.2% [50.3%, 69.3%] | 59/98 |
| wrong feature direction | feature_directions_consistent | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |
| feature outside XAI evidence | feature_claims_supported | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |
| certainty overclaim | certainty_claims_hedged | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |
| completed-action claim | no_completed_action_claims | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |
| invented IP | no_invented_specifics | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |
| invented MAC | no_invented_specifics | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |
| invented date | no_invented_specifics | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |
| invented URL | no_invented_specifics | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |
| limitations removed | uncertainty_present | 98/98 | 100.0% [96.2%, 100.0%] | 98/98 |

Overall: 1333/1372. Missed: 39.
- fake rounding of threshold: 033c0453-e431-5719-8219-6f435787d315 (Benign)
- fake rounding of threshold: 15e00d5f-e1c7-5b90-b2e4-0c40f4e35722 (Web-Based)
- fake rounding of threshold: 22d5e146-9f23-581b-bf09-524728681782 (Recon)
- fake rounding of threshold: 22f34ca7-56b2-59d2-bea9-bc0c5d5041eb (DoS)
- fake rounding of threshold: 39f4837c-706a-52e7-8f8c-df55eb503925 (Spoofing)
- fake rounding of threshold: 428627e6-3419-5e91-a83f-f8b0ab56ac09 (Benign)
- fake rounding of threshold: 442f8b55-e3c9-5a0a-8432-0de4db5a4eef (Spoofing)
- fake rounding of threshold: 4aa09179-ba05-5667-ba21-32fc8c4d290a (Benign)
- fake rounding of threshold: 56e53003-0f0e-5dec-af5a-b199c05bd874 (Brute Force)
- fake rounding of threshold: 629b2dc2-aa13-58d7-991f-4c001bf0bbe1 (Benign)
- fake rounding of threshold: 65c4189f-ae9d-5795-84b0-57a9cba974e5 (Mirai)
- fake rounding of threshold: 6737701e-44c9-588e-88f1-949259631036 (DoS)
- fake rounding of threshold: 69c58b33-9925-5269-b2fe-bbcdfc143a1b (Recon)
- fake rounding of threshold: 6a3bbd25-bfda-5470-a858-773f625bdb21 (DDoS)
- fake rounding of threshold: 7142949e-e660-54cb-adb2-f0c9dc7187d3 (Benign)
- fake rounding of threshold: 7ad4bdb1-580d-5f1f-8126-53b6f8a46d21 (Recon)
- fake rounding of threshold: 8f44299b-f502-55e2-9244-07c9095ffa29 (Web-Based)
- fake rounding of threshold: 9308e165-5f85-50c6-bc60-c3c52c21a9c5 (Benign)
- fake rounding of threshold: 93e81e7f-24e6-5497-9c2a-e178b7d1fde9 (DoS)
- fake rounding of threshold: 94d0deb5-2065-5846-bed7-b68821ae3c5a (Spoofing)
- fake rounding of threshold: 95e4bb50-4f56-55d6-83bf-774852ef3f51 (Benign)
- fake rounding of threshold: 97c90c8d-8f59-57fa-b784-8867b0f749fa (Web-Based)
- fake rounding of threshold: 9e5dd608-3ce9-5a30-a37a-a7a5a0603cde (Web-Based)
- fake rounding of threshold: a0318344-5130-557c-8db1-caa1db28c266 (Benign)
- fake rounding of threshold: a2e1a02f-8907-5496-9d79-e27c7e92637f (Benign)
- fake rounding of threshold: a303a3bc-ff70-5706-b658-27c8ffa232f2 (Spoofing)
- fake rounding of threshold: a79e49ac-991a-5549-8b49-28f625271c86 (Web-Based)
- fake rounding of threshold: b018c3fc-7430-5271-80a8-027eb14fc85e (Brute Force)
- fake rounding of threshold: b0620f9e-4c65-563c-83e3-2988c29f98e4 (Benign)
- fake rounding of threshold: b9f6b646-c1fd-5a3c-a10c-5649e48cc53f (DoS)
- fake rounding of threshold: ba1ba39d-006a-587b-9aa5-092ce9149071 (Recon)
- fake rounding of threshold: c4108aa3-3ded-5e5e-8fa9-3757a0e232da (Recon)
- fake rounding of threshold: c9a0bb36-8d87-5fc7-8a01-11cf82cf865b (Mirai)
- fake rounding of threshold: ca99bc2e-d307-5acd-a625-6c10e41db5c3 (DDoS)
- fake rounding of threshold: ce67c342-b26f-57d9-94f9-90037bc26e76 (Benign)
- fake rounding of threshold: d3772bd4-4ebc-55c6-b810-90f29d9d87b9 (Benign)
- fake rounding of threshold: dcf923eb-c0c0-5614-949a-811839e601db (DoS)
- fake rounding of threshold: e2cebdd5-9c37-5009-9ee6-96dab2e5976c (Web-Based)
- fake rounding of threshold: fcd935c5-e4ea-51ca-b67e-bd9786629969 (Spoofing)
