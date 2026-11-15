import React from 'react';
import { BarChart3, Cpu, Fingerprint, Target, ShieldCheck, Scale, Bot } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

// Every number below is copied from a committed result file (named under each panel). Nothing is computed here.
const tip = { background: '#101b29', border: '1px solid #28374a', borderRadius: 8, color: '#eef4fb' };

const detectorFamilies = [
  { f: 'DDoS', deployed: 100.0, p90: 100.0 }, { f: 'DoS', deployed: 100.0, p90: 100.0 }, { f: 'Mirai*', deployed: 100.0, p90: 100.0 },
  { f: 'Recon', deployed: 56.6, p90: 66.0 }, { f: 'Web-Based*', deployed: 33.9, p90: 47.9 }, { f: 'Spoofing', deployed: 25.7, p90: 37.3 },
  { f: 'Brute Force', deployed: 20.8, p90: 35.5 }, { f: 'Benign (false alarms)', deployed: 5.0, p90: 10.0 },
];
const models = [
  { m: 'Deep SVDD', f1: 0.993 }, { m: 'Autoencoder', f1: 0.951 }, { m: 'Denoising AE', f1: 0.927 },
  { m: 'One-class SVM', f1: 0.912 }, { m: 'Variational AE', f1: 0.888 }, { m: 'Contractive AE', f1: 0.845 },
];
const attackSteps = [
  { s: 'TF-IDF only', score: 0.2215 }, { s: '+ v2 filter', score: 0.2730 }, { s: '+ guarded mapping', score: 0.3050 }, { s: '+ score gate', score: 0.5405 },
];
const policy = [
  { s: 'S10 (10% attacks)', bandit: 0.591, supervised: 0.568 }, { s: 'S30 (30%)', bandit: -0.260, supervised: 0.184 }, { s: 'S58 (58%)', bandit: 0.755, supervised: 1.202 },
];

function Panel({ icon: Icon, tone, title, sub, source, children }) {
  return <section className="panel eval-panel">
    <div className="panel-title"><div className={`icon-box ${tone}`}><Icon size={17} /></div><div><h3>{title}</h3><p>{sub}</p></div></div>
    {children}
    <p className="source-line">Source: {source}</p>
  </section>;
}

export default function Evaluation() {
  return <div className="evaluation">
    <div className="heading-row"><div>
      <div className="eyebrow"><span className="pulse" /> EVALUATION <span className="slash">/</span> MEASURED RESULTS</div>
      <h1>What each stage achieves — and where it falls short</h1>
      <p className="subhead">Every experiment was planned in a committed amendment before it was run, and run once. Negative results are reported alongside positive ones.</p>
    </div></div>

    <div className="eval-grid">
      <Panel icon={Cpu} tone="purple" title="1 · Detector (Deep SVDD, trained on benign only)" sub="Validation: recall 0.9877 · precision 0.9997 · F1 0.9937 · false-alarm rate 5.0%" source="backend/experiments/operating_points/summary.md (amendment 13), model comparison report">
        <div className="chart-wrap"><ResponsiveContainer width="100%" height={250}>
          <BarChart data={detectorFamilies} margin={{ left: 0, right: 8, bottom: 30 }}>
            <CartesianGrid stroke="#1d2a3a" vertical={false} />
            <XAxis dataKey="f" interval={0} angle={-18} textAnchor="end" height={55} tick={{ fill: '#9aabbe', fontSize: 9 }} />
            <YAxis unit="%" tick={{ fill: '#78899d', fontSize: 10 }} />
            <Tooltip contentStyle={tip} formatter={v => `${v}%`} />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            <Bar isAnimationActive={false} dataKey="deployed" name="deployed threshold (95th pct)" fill="#41d3c0" radius={[3, 3, 0, 0]} />
            <Bar isAnimationActive={false} dataKey="p90" name="lower threshold (90th pct)" fill="#70a9ff" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer></div>
        <p className="score-caption">Flagged share per family on all 45.8M rows. *Zero-day test families, never seen in any form during training. The headline recall is dominated by DDoS (34M rows); quiet attacks are caught far less often, and lowering the threshold to the 90th percentile helps only partly while doubling false alarms.</p>
        <table className="mini-table"><thead><tr><th>Model (same data)</th><th>F1</th></tr></thead><tbody>{models.map(x => <tr key={x.m} className={x.m === 'Deep SVDD' ? 'sel' : ''}><td>{x.m}</td><td>{x.f1.toFixed(3)}</td></tr>)}</tbody></table>
      </Panel>

      <Panel icon={Fingerprint} tone="amber" title="2 · Explanation (occlusion)" sub="Is the explanation faithful to the model?" source="ablation_amendment9/xai_deletion.md, xai_benign_reference/summary.md (amendments 9, 14)">
        <table className="mini-table"><thead><tr><th>Test</th><th>Result</th></tr></thead><tbody>
          <tr><td>Reset the top feature</td><td><b>~70% of the score removed</b>; 60–79% of alerts fall below threshold</td></tr>
          <tr><td>Top feature vs a random feature</td><td>+180 points (interval well above 0)</td></tr>
          <tr><td>Reset top 3 / top 5 together</td><td>Score usually <b>rises</b> → model is non-additive</td></tr>
          <tr><td>Benign-median reference (amend. 14)</td><td>Pre-stated rule: <b>NO</b> (still not faithful beyond top feature)</td></tr>
          <tr><td>Agreement with SHAP, top-1 / top-5</td><td>8.4% / 26.0% → <b>15.5% / 35.9%</b> with benign reference</td></tr>
        </tbody></table>
        <p className="score-caption">Use the explanation for its top feature; treat lower ranks as indicative.</p>
      </Panel>

      <Panel icon={Target} tone="blue" title="3 · ATT&CK context" sub="One-time test stream S10c (3,010 flagged alerts, 90% false alarms)" source="mapping_a12/test_s10b.md, mapping_a15/test_s10c.md (amendments 12, 15)">
        <div className="chart-wrap"><ResponsiveContainer width="100%" height={190}>
          <BarChart data={attackSteps} margin={{ left: 0, right: 8 }}>
            <CartesianGrid stroke="#1d2a3a" vertical={false} />
            <XAxis dataKey="s" tick={{ fill: '#9aabbe', fontSize: 9 }} />
            <YAxis domain={[0, 0.6]} tick={{ fill: '#78899d', fontSize: 10 }} />
            <Tooltip contentStyle={tip} formatter={v => Number(v).toFixed(4)} />
            <Bar isAnimationActive={false} dataKey="score" name="primary balanced score" fill="#70a9ff" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer></div>
        <table className="mini-table"><tbody>
          <tr><td>Guarded mapping (S10b, planned test)</td><td><b>+0.031</b> [+0.019, +0.043] · Recon 0 → 17/43</td></tr>
          <tr><td>Score gate (S10c, planned test)</td><td><b>+0.236</b> [+0.221, +0.249] · benign alerts without misleading context 28% → 79%</td></tr>
          <tr><td>Cost of the gate</td><td>Brute Force loses all relevant context (9/43 → 0); Spoofing still 0/43</td></tr>
        </tbody></table>
      </Panel>

      <Panel icon={Bot} tone="cyan" title="4 · LLM report (qwen3:8b, local)" sub="100 alerts · temperature 0 · fixed seed" source="backend/experiments/llm_verification/main_qwen3_8b/summary.md">
        <table className="mini-table"><tbody>
          <tr><td>Valid structured reports</td><td><b>100 / 100</b></td></tr>
          <tr><td>Verifier verdicts</td><td>98 VERIFIED · 2 UNCERTAIN · 0 REJECTED</td></tr>
          <tr><td>Faithful but wrong</td><td><b>47</b> reports repeat an irrelevant retrieved technique</td></tr>
          <tr><td>Speed (CPU)</td><td>about 3 minutes per alert</td></tr>
          <tr><td>Blind human check (32 reports)</td><td>pending</td></tr>
        </tbody></table>
      </Panel>

      <Panel icon={ShieldCheck} tone="cyan" title="5 · Verification (11 rule checks)" sub="Does it catch reports that misstate the evidence?" source="main_qwen3_8b/damage_test.md">
        <table className="mini-table"><tbody>
          <tr><td>Planted errors caught (damage test)</td><td><b>1,333 / 1,372 (97.2%)</b></td></tr>
          <tr><td>Weakest error type</td><td>subtle number rounding, 60% caught</td></tr>
          <tr><td>False alarms removed</td><td><b>0 / 30</b> — it checks faithfulness, not truth</td></tr>
          <tr><td>As a policy input</td><td>constant (1.0) in every replay stream → never tested as a signal</td></tr>
        </tbody></table>
      </Panel>

      <Panel icon={Scale} tone="purple" title="6 · Response policy (LinUCB bandit)" sub="Mean designed reward per alert; 5 seeds × 5 folds" source="docs/stage10-results.md, tradeoff_analysis/tradeoff.md, ablation_amendment9/policy.md">
        <div className="chart-wrap"><ResponsiveContainer width="100%" height={190}>
          <BarChart data={policy} margin={{ left: 0, right: 8 }}>
            <CartesianGrid stroke="#1d2a3a" vertical={false} />
            <XAxis dataKey="s" tick={{ fill: '#9aabbe', fontSize: 9 }} />
            <YAxis tick={{ fill: '#78899d', fontSize: 10 }} />
            <Tooltip contentStyle={tip} formatter={v => Number(v).toFixed(3)} />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            <Bar isAnimationActive={false} dataKey="bandit" name="LinUCB bandit" fill="#41d3c0" radius={[3, 3, 0, 0]} />
            <Bar isAnimationActive={false} dataKey="supervised" name="supervised policy" fill="#b79aff" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer></div>
        <p className="score-caption">The bandit beats always-review, random and the best fixed action on all streams, but loses to a supervised policy at 30% and 58% attacks. At 30% it misses fewer attacks (18.1% vs 26.6%) but sends more alerts to analysts (62% vs 37%); it wins only if a missed attack costs more than −23.4. Rewards are designed, not measured costs.</p>
      </Panel>
    </div>
    <div className="notice honest"><BarChart3 size={15} /><span>All results come from one dataset (CIC-IoT-2023, one lab testbed) and one detector checkpoint. Real-network deployment would need a matching feature extractor, the training scaler, and a threshold recalibrated on that network’s normal traffic.</span></div>
  </div>;
}
