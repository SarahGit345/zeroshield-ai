import React from 'react';
import { Bot, CheckCircle2, Fingerprint, Gauge, ShieldCheck, Target, XCircle, Scale } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { ACTION_COLORS, ACTION_LABELS, fmt } from '../api';

const REPORT_FIELDS = [
  ['Incident summary', 'incident_summary'], ['Evidence', 'evidence'], ['ATT&CK context', 'attack_context'],
  ['Interpretation', 'interpretation'], ['Recommended analyst action', 'recommended_action'], ['Limitations', 'limitations'],
];

function Section({ icon: Icon, tone, title, sub, children, step }) {
  return (
    <section className="panel detail-section">
      <div className="panel-title">
        <div className={`icon-box ${tone}`}><Icon size={17} /></div>
        <div><h3>{title}</h3><p>{sub}</p></div>
        {step && <span className="step">{step}</span>}
      </div>
      {children}
    </section>
  );
}

export default function AlertDetail({ item }) {
  if (!item) {
    return <div className="panel empty-detail"><Gauge size={26} /><b>Select a flow</b><span>Click any row in the feed to see how each stage of the pipeline handled it.</span></div>;
  }
  const { anomaly_score: score, threshold, detected, top_features: feats = [], mitre = {}, reasoning = {}, verification = {}, bandit = {}, ground_truth: truth, simulated_feedback: fb } = item;
  const ratio = score / threshold;
  const bars = feats.map(f => ({ name: f.feature, value: f.contribution }));
  const checks = verification.checks || [];
  const actionScores = Object.entries(bandit.action_scores || {}).sort((a, b) => b[1] - a[1]);
  const correct = truth ? (detected === truth.is_attack) : null;
  return (
    <div className="detail-stack">
      <div className={`result-banner ${detected ? 'danger' : 'safe'}`}>
        <div className="result-symbol">{detected ? <XCircle size={20} /> : <CheckCircle2 size={20} />}</div>
        <div><small>FLOW #{item.replay_index} · DEEP SVDD</small><h2>{detected ? 'ALERT RAISED' : 'BELOW THRESHOLD · NO ALERT'}</h2></div>
        <span className="result-tag">score {fmt(score, 4)} · {fmt(ratio, 2)}× threshold</span>
      </div>

      <Section icon={Gauge} tone="purple" title="1 · Detection" sub="Squared distance from the benign centre; alert if score ≥ threshold" step="DETECTOR">
        <div className="score-cards"><div><small>ANOMALY SCORE</small><b>{fmt(score, 6)}</b></div><div><small>THRESHOLD (95th pct benign)</small><b>{fmt(threshold, 6)}</b></div></div>
        <p className="score-caption">An anomaly score, not a probability. The detector was trained on benign traffic only; it has never seen any attack.</p>
      </Section>

      <Section icon={Fingerprint} tone="amber" title="2 · Explanation (occlusion XAI)" sub="Score drop when each feature is reset to the scaled mean · top 10" step="WHY">
        {detected || feats.length ? <>
          <div className="chart-wrap"><ResponsiveContainer width="100%" height={Math.max(160, bars.length * 22)}>
            <BarChart data={bars} layout="vertical" margin={{ left: 4, right: 16, top: 2, bottom: 2 }}>
              <CartesianGrid stroke="#1d2a3a" horizontal={false} />
              <XAxis type="number" tick={{ fill: '#78899d', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" width={120} tick={{ fill: '#bac6d5', fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: '#101b29', border: '1px solid #28374a', borderRadius: 8, color: '#eef4fb' }} formatter={v => Number(v).toFixed(6)} />
              <Bar isAnimationActive={false} dataKey="value" radius={[0, 4, 4, 0]}>{bars.map((x, i) => <Cell key={i} fill={i === 0 ? '#f4be70' : x.value >= 0 ? '#35c5b2' : '#62738a'} />)}</Bar>
            </BarChart>
          </ResponsiveContainer></div>
          <p className="score-caption">Measured reliability: resetting the <b>top</b> feature removes about 70% of the score (amendment 9). Lower-ranked features are less reliable because the model is non-additive (amendment 14).</p>
        </> : <p className="muted-line">No explanation needed below the threshold.</p>}
      </Section>

      <Section icon={Target} tone="blue" title="3 · ATT&CK context" sub={`Behaviour retrieval · mode: ${mitre.attack_mode || 'default'}${mitre.mapping_variant ? ` · map ${mitre.mapping_variant}` : ''}`} step="CONTEXT">
        {mitre.techniques?.length ? <div className="tech-list">{mitre.techniques.map(t => (
          <div className="tech-row" key={t.technique_id}>
            <b>{t.technique_id}</b><span>{t.technique_name}</span>
            {t.candidate_source && <em className={`src-${t.candidate_source}`}>{t.candidate_source}</em>}
            {t.similarity > 0 && <small>sim {fmt(t.similarity, 2)}</small>}
          </div>))}</div>
          : <p className="muted-line">{mitre.message || 'No technique asserted.'}</p>}
        {mitre.query && <p className="score-caption">Behaviour query: “{mitre.query}”</p>}
        {mitre.score_gate && <p className="score-caption">Score gate {mitre.score_gate.gate}: context shown only if score ≥ {fmt(mitre.score_gate.minimum_score, 4)}.</p>}
        <p className="score-caption">Candidates are context, not a classification.</p>
      </Section>

      <Section icon={Bot} tone="cyan" title="4 · Analyst report" sub={reasoning.mode || 'Report'} step="REPORT">
        {reasoning.report ? <div className="report-grid">{REPORT_FIELDS.map(([label, key]) => (
          <div key={key}><h4>{label}</h4>{Array.isArray(reasoning.report[key]) ? <ul>{reasoning.report[key].map((v, i) => <li key={i}>{v}</li>)}</ul> : <p>{reasoning.report[key]}</p>}</div>
        ))}</div> : <p className="muted-line">No report.</p>}
      </Section>

      <Section icon={ShieldCheck} tone="cyan" title={`5 · Verification · ${verification.verdict || '—'}`} sub="Rule checks of the report against the evidence it was given" step="CHECK">
        <div className="check-grid">{checks.map(c => (
          <div key={c.name} className={`check ${c.passed ? 'ok' : 'bad'}`} title={c.detail}>
            {c.passed ? <CheckCircle2 size={13} /> : <XCircle size={13} />}<span>{c.name.replaceAll('_', ' ')}</span><small>{c.level}</small>
          </div>))}</div>
        <p className="score-caption">Checks faithfulness to the evidence, not truth: a report can be faithful and still wrong.</p>
      </Section>

      <Section icon={Scale} tone="purple" title="6 · Response policy (simulated)" sub={`${bandit.policy_version || ''} · ${bandit.selection_mode || ''}`} step="ACT">
        <div className="action-pick" style={{ borderColor: ACTION_COLORS[bandit.selected_action] }}>
          <small>SELECTED</small><b style={{ color: ACTION_COLORS[bandit.selected_action] }}>{ACTION_LABELS[bandit.selected_action] || bandit.selected_action}</b>
          <span>{bandit.reason}</span>
        </div>
        {actionScores.length > 0 && <table className="mini-table"><thead><tr><th>ACTION</th><th>LINUCB SCORE</th></tr></thead><tbody>
          {actionScores.map(([a, s]) => <tr key={a} className={a === bandit.selected_action ? 'sel' : ''}><td>{ACTION_LABELS[a] || a}</td><td>{fmt(s, 4)}</td></tr>)}
        </tbody></table>}
        <p className="simulation-label">SIMULATED — no real network action is executed. Status: {bandit.simulated_execution_status}</p>
      </Section>

      {truth && <section className={`panel truth-panel ${correct ? 'right' : 'wrong'}`}>
        <div><small>DATASET LABEL · revealed after the decision</small><b>{truth.label}</b><span>{truth.family}{truth.is_attack ? ' · attack' : ' · benign'}</span></div>
        <div><small>DETECTOR VERDICT</small><b>{detected ? (truth.is_attack ? 'True positive' : 'False positive') : (truth.is_attack ? 'Missed attack' : 'True negative')}</b>
          {fb && <span>Simulated feedback · reward {fmt(fb.reward, 0)}{fb.reviewer_choice ? ` · reviewer ${fb.reviewer_choice.toLowerCase()}` : ''}</span>}</div>
      </section>}
    </div>
  );
}
