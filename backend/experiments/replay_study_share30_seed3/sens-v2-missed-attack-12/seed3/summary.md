# Stage 7 replay summary

Stream: experiments\replay_streams\replay_stream_share30_seed3.jsonl. 1411 flows, of which 1003 were flagged by the detector and routed to the response policy; 258 unflagged attack flow(s) and 150 unflagged benign flow(s) never became alerts and are not scored.

Evaluation: 5-fold, every routed alert evaluated once by a policy that did not train on it. Reward table: sens-v2-missed-attack-12. Seed: 3.

Bandit mean reward -0.48 per alert (fold std 0.34); verification-gate rule (strawman on this stream) -6.90. See policy_comparison_metrics.json.

The reward values are designed simulation trade-offs, not real-world costs. This response policy does not change or improve detector accuracy. No statistical significance is claimed, and a stream this small supports no general performance claim. Asset criticality and analyst history are unavailable and were not fabricated. CONFIRM_TO_ACT is assumed approved in the simulator; live alerts stay pending until an analyst decides.
