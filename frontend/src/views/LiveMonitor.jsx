import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Activity, AlertTriangle, Pause, Play, RotateCcw, SkipForward, Info } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, ReferenceLine, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis } from 'recharts';
import { ACTION_COLORS, ACTION_LABELS, fmt, getJson, pct, postJson } from '../api';
import AlertDetail from '../components/AlertDetail';

const FAMILIES = ['Benign', 'DDoS', 'DoS', 'Mirai', 'Recon', 'Brute Force', 'Spoofing', 'Web-Based'];
const MODES = {
  default: 'Published retrieval (TF-IDF)',
  guarded: 'Guarded mapping (amendment 12)',
  gated: 'Guarded + score gate (amendment 15)',
};
const KEEP = 400;

const emptyStats = () => ({
  flows: 0, alerts: 0, tp: 0, fp: 0, fn: 0, tn: 0, verified: 0, rewardSum: 0, rewardN: 0, withContext: 0,
  family: Object.fromEntries(FAMILIES.map(f => [f, { n: 0, flagged: 0 }])),
  actions: { AUTO_REMEDIATE: 0, CONFIRM_TO_ACT: 0, HUMAN_REVIEW: 0, MONITOR_ONLY: 0 },
  rewardSeries: [],
});

function accumulate(stats, r) {
  const s = { ...stats, family: { ...stats.family }, actions: { ...stats.actions } };
  const fam = r.ground_truth?.family || 'Unknown';
  const attack = !!r.ground_truth?.is_attack;
  s.flows += 1;
  s.family[fam] = { n: (s.family[fam]?.n || 0) + 1, flagged: (s.family[fam]?.flagged || 0) + (r.detected ? 1 : 0) };
  if (r.detected) {
    s.alerts += 1;
    attack ? (s.tp += 1) : (s.fp += 1);
    if (r.verification?.verdict === 'VERIFIED') s.verified += 1;
    if (r.mitre?.techniques?.length) s.withContext += 1;
    const a = r.bandit?.selected_action;
    if (a in s.actions) s.actions[a] += 1;
  } else {
    attack ? (s.fn += 1) : (s.tn += 1);
  }
  if (r.simulated_feedback && r.simulated_feedback.reward !== null && r.simulated_feedback.reward !== undefined) {
    s.rewardSum += Number(r.simulated_feedback.reward);
    s.rewardN += 1;
    s.rewardSeries = [...s.rewardSeries.slice(-299), { n: s.rewardN, mean: s.rewardSum / s.rewardN }];
  }
  return s;
}

function Kpi({ label, value, sub, tone }) {
  return <div className="kpi"><small>{label}</small><b className={tone || ''}>{value}</b>{sub && <span>{sub}</span>}</div>;
}

export default function LiveMonitor() {
  const [status, setStatus] = useState(null);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [speed, setSpeed] = useState(2);
  const [mode, setMode] = useState('default');
  const [learn, setLearn] = useState(true);
  const [items, setItems] = useState([]);
  const [stats, setStats] = useState(emptyStats);
  const [selected, setSelected] = useState(null);
  const busy = useRef(false);

  const loadStatus = useCallback(() => getJson('/live/status').then(setStatus).catch(e => setError(`Backend not reachable: ${e.message}`)), []);
  useEffect(() => { loadStatus(); }, [loadStatus]);

  const step = useCallback(async (count = 1) => {
    if (busy.current) return;
    busy.current = true;
    try {
      const data = await postJson('/live/next', { count, attack_mode: mode, learn });
      setItems(prev => [...data.results.slice().reverse(), ...prev].slice(0, KEEP));
      setStats(prev => data.results.reduce(accumulate, prev));
      setStatus(s => (s ? { ...s, cursor: data.cursor, policy_updates: data.policy_updates } : s));
      const lastAlert = [...data.results].reverse().find(r => r.detected);
      setSelected(sel => (sel === null && lastAlert ? lastAlert.alert_id : sel));
      setError('');
    } catch (e) {
      setError(e.message.includes('fetch') ? 'Could not reach the backend at http://localhost:8000.' : e.message);
      setRunning(false);
    } finally {
      busy.current = false;
    }
  }, [mode, learn]);

  useEffect(() => {
    if (!running) return undefined;
    const interval = Math.max(250, 1000 / speed);
    const count = Math.max(1, Math.round((speed * interval) / 1000));
    const t = setInterval(() => step(count), interval);
    return () => clearInterval(t);
  }, [running, speed, step]);

  async function reset() {
    setRunning(false);
    try {
      await postJson('/live/reset?reset_policy=true');
      setItems([]); setStats(emptyStats()); setSelected(null); loadStatus();
    } catch (e) { setError(e.message); }
  }

  const chosen = items.find(x => x.alert_id === selected) || items.find(x => x.detected) || null;
  const timeline = useMemo(() => items.slice(0, 200).map((r, i) => ({
    i: stats.flows - i, score: Math.max(r.anomaly_score, 1e-4), attack: r.ground_truth?.is_attack, id: r.alert_id, family: r.ground_truth?.family,
  })), [items, stats.flows]);
  const threshold = items[0]?.threshold ?? 0.06141921002417763;
  const actionData = Object.entries(stats.actions).map(([k, v]) => ({ name: ACTION_LABELS[k], key: k, v }));
  const attacks = stats.tp + stats.fn;
  const benign = stats.fp + stats.tn;

  return (
    <div className="live">
      <div className="heading-row">
        <div>
          <div className="eyebrow"><span className={running ? 'pulse' : 'pulse idle'} /> LIVE MONITOR <span className="slash">/</span> RECORDED-FLOW REPLAY</div>
          <h1>Live traffic monitor</h1>
          <p className="subhead">Each flow goes through the full pipeline: detector → explanation → ATT&amp;CK → report → verification → response policy.</p>
        </div>
      </div>

      <div className="notice honest"><Info size={15} /><span>
        <b>What you are seeing:</b> real CIC-IoT-2023 flows ({status?.total ?? '…'} rows, scaled feature space) replayed one at a time in a fixed order —
        not live packet capture. Within each family, the share the detector flags equals its flag rate on all 45.8M rows; the mix between families
        ({status?.composition ? Object.entries(status.composition).map(([k, v]) => `${k} ${v}`).join(', ') : '…'}) is stratified, not real-network proportions.
        The dataset label is shown only after the pipeline has decided. All actions are simulated.
      </span></div>
      {status && !status.available && <div className="error-box"><AlertTriangle size={15} />{status.error}</div>}
      {error && <div className="error-box"><AlertTriangle size={15} />{error}</div>}

      <div className="panel controls">
        <button className={`control-main ${running ? 'stop' : ''}`} onClick={() => setRunning(r => !r)} disabled={!status?.available}>
          {running ? <><Pause size={15} /> Pause</> : <><Play size={15} /> Start replay</>}
        </button>
        <button className="secondary-button" onClick={() => step(1)} disabled={running || !status?.available}><SkipForward size={13} /> Step one flow</button>
        <label>Speed<select value={speed} onChange={e => setSpeed(Number(e.target.value))}>{[1, 2, 5, 10, 20].map(v => <option key={v} value={v}>{v} flows/s</option>)}</select></label>
        <label>ATT&amp;CK mode<select value={mode} onChange={e => setMode(e.target.value)}>{Object.entries(MODES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
        <label className="check-label"><input type="checkbox" checked={learn} onChange={e => setLearn(e.target.checked)} /> Simulated analyst feedback (policy learns)</label>
        <button className="secondary-button" onClick={reset}><RotateCcw size={13} /> Reset</button>
        <span className="cursor-tag">flow {status?.cursor ?? 0} / {status?.total ?? 0} · policy updates {status?.policy_updates ?? 0} · reports: template</span>
      </div>

      <div className="kpi-grid">
        <Kpi label="FLOWS PROCESSED" value={stats.flows} sub={`${stats.alerts} alerts (${pct(stats.alerts, stats.flows)})`} />
        <Kpi label="ATTACK FLOWS FLAGGED" value={pct(stats.tp, attacks)} sub={`${stats.tp} of ${attacks} attack flows`} tone="good" />
        <Kpi label="BENIGN FLOWS FLAGGED" value={pct(stats.fp, benign)} sub={`${stats.fp} of ${benign} benign flows · full-data rate 5.0%`} tone={stats.fp ? 'warn' : ''} />
        <Kpi label="ALERTS THAT WERE ATTACKS" value={pct(stats.tp, stats.alerts)} sub="depends on the family mix (stratified here)" />
        <Kpi label="REPORTS VERIFIED" value={pct(stats.verified, stats.alerts)} sub={`${stats.verified} of ${stats.alerts} alerts`} />
        <Kpi label="ALERTS WITH ATT&CK" value={pct(stats.withContext, stats.alerts)} sub={`current mode: ${MODES[mode]}`} />
        <Kpi label="MEAN REWARD" value={stats.rewardN ? fmt(stats.rewardSum / stats.rewardN, 3) : '—'} sub={learn ? `${stats.rewardN} rewarded alerts (designed rewards)` : 'feedback off'} />
      </div>

      <div className="live-grid">
        <section className="panel">
          <div className="panel-title"><div className="icon-box purple"><Activity size={17} /></div><div><h3>Anomaly score timeline</h3><p>Last 200 flows · log scale · dashed line = threshold · colour = dataset label</p></div></div>
          <div className="chart-wrap"><ResponsiveContainer width="100%" height={250}>
            <ScatterChart margin={{ left: 0, right: 12, top: 8, bottom: 4 }}>
              <CartesianGrid stroke="#1d2a3a" />
              <XAxis dataKey="i" type="number" domain={['dataMin', 'dataMax']} tick={{ fill: '#78899d', fontSize: 10 }} name="flow" />
              <YAxis dataKey="score" type="number" scale="log" domain={[0.001, 'auto']} allowDataOverflow tick={{ fill: '#78899d', fontSize: 10 }} tickFormatter={v => (v >= 1 ? v.toFixed(0) : v.toPrecision(1))} name="score" />
              <ZAxis range={[28, 28]} />
              <Tooltip cursor={{ strokeDasharray: '3 3' }} contentStyle={{ background: '#101b29', border: '1px solid #28374a', borderRadius: 8, color: '#eef4fb' }}
                formatter={(v, n) => (n === 'score' ? Number(v).toFixed(4) : v)} labelFormatter={() => ''} />
              <ReferenceLine y={threshold} stroke="#f4bb67" strokeDasharray="5 4" />
              {mode === 'gated' && <ReferenceLine y={threshold * 3} stroke="#70a9ff" strokeDasharray="2 5" />}
              <Scatter isAnimationActive={false} data={timeline} onClick={p => setSelected(p.id)}>
                {timeline.map(p => <Cell key={p.id} fill={p.attack ? '#ff7a85' : '#35c5b2'} cursor="pointer" />)}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer></div>
          <div className="legend"><span><i style={{ background: '#ff7a85' }} />attack (label)</span><span><i style={{ background: '#35c5b2' }} />benign (label)</span><span><i className="dash" />threshold {fmt(threshold, 4)}</span>{mode === 'gated' && <span><i className="dash blue" />ATT&amp;CK gate (3× threshold)</span>}</div>
        </section>

        <section className="panel">
          <div className="panel-title"><div className="icon-box cyan"><Activity size={17} /></div><div><h3>Response actions (simulated)</h3><p>Chosen by the LinUCB policy for verified alerts</p></div></div>
          <div className="chart-wrap"><ResponsiveContainer width="100%" height={150}>
            <BarChart data={actionData} layout="vertical" margin={{ left: 6, right: 16 }}>
              <XAxis type="number" allowDecimals={false} tick={{ fill: '#78899d', fontSize: 10 }} />
              <YAxis type="category" dataKey="name" width={150} tick={{ fill: '#bac6d5', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#101b29', border: '1px solid #28374a', borderRadius: 8, color: '#eef4fb' }} />
              <Bar isAnimationActive={false} dataKey="v" name="alerts" radius={[0, 4, 4, 0]}>{actionData.map(d => <Cell key={d.key} fill={ACTION_COLORS[d.key]} />)}</Bar>
            </BarChart>
          </ResponsiveContainer></div>
          <p className="score-caption">The action mix follows the attack share among alerts: here {pct(stats.tp, stats.alerts, 0)} of alerts are attacks, so a learning policy moves toward containment. In the 10%-attack study stream (S10) it learned the opposite: it monitors most alerts (analyst workload 8.2%) and misses 51.4% of attacks (tradeoff.md).</p>
          {learn && stats.rewardSeries.length > 1 && <>
            <p className="mini-title">Mean reward per rewarded alert (policy learning)</p>
            <div className="chart-wrap"><ResponsiveContainer width="100%" height={110}>
              <LineChart data={stats.rewardSeries} margin={{ left: 0, right: 12, top: 4 }}>
                <CartesianGrid stroke="#1d2a3a" />
                <XAxis dataKey="n" tick={{ fill: '#78899d', fontSize: 9 }} />
                <YAxis tick={{ fill: '#78899d', fontSize: 9 }} width={36} />
                <Tooltip contentStyle={{ background: '#101b29', border: '1px solid #28374a', borderRadius: 8, color: '#eef4fb' }} formatter={v => Number(v).toFixed(3)} />
                <ReferenceLine y={0} stroke="#3a4a5d" />
                <Line isAnimationActive={false} dataKey="mean" dot={false} stroke="#41d3c0" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer></div>
          </>}
        </section>
      </div>

      <section className="panel">
        <div className="panel-title"><div className="icon-box amber"><Activity size={17} /></div><div><h3>Detection by family (this session)</h3><p>Share of each family's flows flagged by the detector · labels used only to score</p></div></div>
        <div className="family-bars">{FAMILIES.map(f => {
          const v = stats.family[f] || { n: 0, flagged: 0 };
          const rate = v.n ? v.flagged / v.n : 0;
          return <div key={f} className="fam-row"><span>{f}</span><div className="fam-track"><div className={f === 'Benign' ? 'fam-fill benign' : 'fam-fill'} style={{ width: `${100 * rate}%` }} /></div><b>{v.n ? pct(v.flagged, v.n, 0) : '—'}</b><small>{v.flagged}/{v.n}</small></div>;
        })}</div>
        <p className="score-caption">For Benign the bar is the false-alarm rate. Quiet attacks (Recon, Brute Force, Spoofing, Web-Based) are caught far less often than floods — the same pattern as the full-data analysis (amendment 13).</p>
      </section>

      <div className="feed-detail">
        <section className="panel feed">
          <div className="panel-title"><div className="icon-box blue"><Activity size={17} /></div><div><h3>Flow feed</h3><p>Newest first · click a row for the full pipeline trace</p></div></div>
          <div className="table-wrap feed-table"><table>
            <thead><tr><th>#</th><th>SCORE</th><th>DETECTOR</th><th>VERIFY</th><th>ACTION</th><th>TOP ATT&amp;CK</th><th>LABEL</th></tr></thead>
            <tbody>{items.slice(0, 120).map(r => {
              const ok = r.ground_truth ? r.detected === r.ground_truth.is_attack : null;
              return <tr key={r.alert_id} className={`${r.alert_id === selected ? 'sel' : ''} ${r.detected ? 'alert-row' : ''}`} onClick={() => setSelected(r.alert_id)}>
                <td>{r.replay_index}</td>
                <td className="mono">{fmt(r.anomaly_score, 4)}</td>
                <td>{r.detected ? <span className="pill red">ALERT</span> : <span className="pill">normal</span>}</td>
                <td>{r.detected ? <span className={`pill ${r.verification?.verdict === 'VERIFIED' ? 'green' : 'amber'}`}>{r.verification?.verdict}</span> : '—'}</td>
                <td>{r.detected ? <span style={{ color: ACTION_COLORS[r.bandit?.selected_action] }}>{ACTION_LABELS[r.bandit?.selected_action] || r.bandit?.selected_action}</span> : '—'}</td>
                <td className="mono">{r.detected ? (r.mitre?.techniques?.[0]?.technique_id || 'none') : '—'}</td>
                <td><span className={ok ? 'lbl ok' : 'lbl bad'}>{r.ground_truth?.family}</span></td>
              </tr>;
            })}</tbody>
          </table>{!items.length && <div className="empty-evidence">Press <b>Start replay</b> or <b>Step one flow</b>.</div>}</div>
        </section>
        <div className="detail"><AlertDetail item={chosen} /></div>
      </div>
    </div>
  );
}
