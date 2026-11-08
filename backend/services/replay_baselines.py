"""Fold-fitted baselines for the offline replay (docs/stage10-evaluation-plan.md, B3-B5).

Each policy is fitted on ONE fold's training alerts and their labels, then decides held-out alerts.
`fit(alerts, labels, table)` receives the cleaned alerts (no `_` keys) and the labels as a separate
list; `act(alert)` receives only the cleaned alert. A label therefore cannot reach a decision.

These baselines learn from full-information labels (every action's reward is computable for a
labelled training alert). The bandit only observes the reward of the action it chose. That gives
the baselines an advantage, which is the point: they are strong comparators, not strawmen.
"""
from __future__ import annotations

import numpy as np

from services.bandit_service import ACTIONS, build_context

TIER_QUANTILES = tuple(round(0.05 * i, 2) for i in range(1, 20))      # 0.05 ... 0.95


def auto_eligible(alert: dict) -> bool:
    """Same safety mask as BanditService.select: AUTO only for a detected, confidently verified alert."""
    return bool(alert.get("detected")) and float(alert.get("verification_confidence", 0)) >= 0.85


def pick(scores, alert) -> str:
    """Highest score among allowed actions; ties go to the earlier action in ACTIONS."""
    allowed = [a for a in ACTIONS if a != "AUTO_REMEDIATE" or auto_eligible(alert)]
    return max(allowed, key=lambda a: (scores[a], -ACTIONS.index(a)))


def reward_matrix(labels, table) -> np.ndarray:
    return np.array([[table["attack" if y else "benign"][a] for a in ACTIONS] for y in labels], dtype=float)


class BestConstantAction:
    """B3: the action with the best mean reward on the training alerts (mask applied per alert)."""
    name = "Best constant action (training folds)"

    def fit(self, alerts, labels, table):
        self.means = dict(zip(ACTIONS, reward_matrix(labels, table).mean(axis=0)))
        return self

    def act(self, alert):
        return {"selected_action": pick(self.means, alert), "action_scores": dict(self.means),
                "selection_mode": "constant action ranked on training folds"}


class SupervisedExpectedReward:
    """B4: logistic regression for P(attack) on the 6 non-constant context features, then the action
    with the highest expected reward under the reward table (mask applied)."""
    name = "Supervised expected-reward (logistic, training folds)"

    def fit(self, alerts, labels, table):
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler
        self.table = table
        y = np.array(labels, dtype=int)
        X = np.array([build_context(a)[1:] for a in alerts], dtype=float)
        self.constant_p = None
        if len(set(y.tolist())) < 2:                    # one class in training: predict its rate
            self.constant_p = float(y.mean())
            return self
        self.scaler = StandardScaler().fit(X)
        self.model = LogisticRegression(C=1.0, penalty="l2", solver="lbfgs", max_iter=1000).fit(self.scaler.transform(X), y)
        return self

    def p_attack(self, alert) -> float:
        if self.constant_p is not None: return self.constant_p
        x = self.scaler.transform(np.array([build_context(alert)[1:]], dtype=float))
        return float(self.model.predict_proba(x)[0, 1])

    def act(self, alert):
        p = self.p_attack(alert)
        scores = {a: p * self.table["attack"][a] + (1 - p) * self.table["benign"][a] for a in ACTIONS}
        return {"selected_action": pick(scores, alert), "action_scores": scores, "p_attack": p,
                "selection_mode": "expected reward from logistic P(attack)"}


class ScoreTierRule:
    """B5: up to three tiers of normalized_score with cut points c1 <= c2 from the training quantiles
    0.05..0.95; each tier takes its best training action; the pair with the best training mean wins
    (ties: first pair in grid order). A held-out alert whose tier was empty in training uses the
    training-wide action ranking."""
    name = "Tuned score-tier rule (training folds)"

    def fit(self, alerts, labels, table):
        s = np.array([build_context(a)[1] for a in alerts], dtype=float)
        R = reward_matrix(labels, table)
        eligible = np.array([auto_eligible(a) for a in alerts])
        self.overall = dict(zip(ACTIONS, R.mean(axis=0)))
        cuts = np.quantile(s, TIER_QUANTILES)
        best = None
        for i in range(len(cuts)):
            for j in range(i, len(cuts)):
                c1, c2 = float(cuts[i]), float(cuts[j])
                tiers = np.where(s < c1, 0, np.where(s < c2, 1, 2))
                means, total = {}, 0.0
                for t in (0, 1, 2):
                    member = tiers == t
                    if not member.any(): continue
                    means[t] = dict(zip(ACTIONS, R[member].mean(axis=0)))
                    for elig in (True, False):
                        rows = member & (eligible == elig)
                        if rows.any():
                            action = pick(means[t], {"detected": elig, "verification_confidence": 1.0 if elig else 0.0})
                            total += R[rows, ACTIONS.index(action)].sum()
                if best is None or total > best[0] + 1e-12:
                    best = (total, c1, c2, means)
        self.train_mean_reward = best[0] / len(alerts)
        _, self.c1, self.c2, self.tier_means = best
        return self

    def tier(self, alert) -> int:
        s = build_context(alert)[1]
        return 0 if s < self.c1 else 1 if s < self.c2 else 2

    def act(self, alert):
        t = self.tier(alert)
        scores = self.tier_means.get(t, self.overall)
        return {"selected_action": pick(scores, alert), "action_scores": dict(scores), "tier": t,
                "cut_points": [self.c1, self.c2], "selection_mode": "score tiers tuned on training folds"}


FOLD_BASELINES = (BestConstantAction, SupervisedExpectedReward, ScoreTierRule)
