// views-policy.jsx, Policy Replay + Profile + Environment + Closure + Appraisal.

const { Card: PoCard, KV: PoKV, Tag: PoTag, Badge: PoBadge, Hr: PoHr, Sev: PoSev,
        Kpi: PoKpi, Tabs: PoTabs, Pagination: PoPgn, usePaged: poUsePaged,
        EvBind: PoEv, Callout: PoCallout, Code: PoCode, EmptyState: PoEmpty } = window.UI;
const { HashChip: PoHash, OriginChip: PoOrigin, EvBind2: PoEvBind2,
        DetailRow: PoDetail, StatGrid: PoSGrid, Stat: PoStat,
        ChecksList: PoChecks } = window.UIX;
const Pop = window.PQCP;
const PoS = window.STORE;
const { useState: poS, useMemo: poM } = React;

function PolicyView({ session, pack }) {
  const [tab, setTab] = poS("policy");
  const policy = PoS.policyResult(pack);
  const profile = PoS.assuranceProfile(pack);
  const quality = PoS.evidenceQuality(pack);
  const appraisal = PoS.appraisalResult(pack);
  const closure = PoS.claimClosure(pack);
  const env = PoS.environmentResult(pack);

  // Failure aggregation
  const totalFails = [policy, profile, appraisal, closure, env, quality].reduce(
    (n, x) => n + (x?.failures?.length || 0), 0);

  return (
    <>
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <PoKpi label="Policy" status={policy?.passed === false ? "err" : policy?.passed ? "ok" : "warn"}
               value={policy ? (policy.passed ? "pass" : "fail") : "n/a"}
               sub={policy ? `${(policy.checks || []).length} checks` : "awaiting pqc_policy_result.json"}
               evbind={<PoEvBind2 ev={policy?.evbind} compact />} />
        <PoKpi label="Profile" status={profile?.passed === false ? "err" : profile?.passed ? "ok" : "warn"}
               value={profile ? (profile.passed ? "pass" : "fail") : "n/a"}
               sub={profile ? `${profile.summary?.checks ?? "?"} checks · ${profile.summary?.assets ?? "?"} assets` : "awaiting pqc_assurance_profile_result.json"}
               evbind={<PoEvBind2 ev={profile?.evbind} compact />} />
        <PoKpi label="Evidence quality" status={quality?.passed === false ? "err" : quality?.passed ? "ok" : "warn"}
               value={quality ? (quality.passed ? "pass" : "fail") : "n/a"}
               sub={quality ? `${(quality.checks || []).length} mappings` : "awaiting pqc_evidence_quality_result.json"}
               evbind={<PoEvBind2 ev={quality?.evbind} compact />} />
        <PoKpi label="Appraisal" status={appraisal?.passed === false ? "err" : appraisal?.passed ? "ok" : "warn"}
               value={appraisal ? (appraisal.passed ? "pass" : "fail") : "n/a"}
               sub={appraisal?.mode ? `mode: ${appraisal.mode}` : "awaiting pqc_appraisal_result.json"}
               evbind={<PoEvBind2 ev={appraisal?.evbind} compact />} />
        <PoKpi label="Environment" status={env?.passed === false ? "err" : env?.passed ? "ok" : "warn"}
               value={env ? (env.passed ? "pass" : "fail") : "n/a"}
               sub={env ? `${(env.checks || []).length} checks` : "awaiting pqc_environment_result.json"}
               evbind={<PoEvBind2 ev={env?.evbind} compact />} />
      </div>

      <div className="grid grid-12">
        <PoCard span={12} kicker="Policy replay" title={totalFails === 0 ? "All enforcement layers replay verified" : `${totalFails} failure(s) across enforcement layers`}
              subtitle="Five separate enforcement layers verify the release pack: policy, profile, evidence-quality mapping, environment pinning, and mode appraisal."
              padded={false}
              actions={<PoTabs value={tab} onChange={setTab} tabs={[
                { id: "policy",   label: "Policy",    count: policy ? policy.checks.length : 0 },
                { id: "profile",  label: "Profile",   count: profile ? profile.checks.length : 0 },
                { id: "quality",  label: "Quality",   count: quality ? quality.checks.length : 0 },
                { id: "appraisal", label: "Appraisal", count: appraisal ? appraisal.checks.length : 0 },
                { id: "env",      label: "Env",       count: env ? env.checks.length : 0 },
                { id: "closure",  label: "Closure",   count: closure ? closure.checks.length : 0 },
              ]} />}>

          {tab === "policy" && <PolicyTab policy={policy} />}
          {tab === "profile" && <ProfileTab profile={profile} />}
          {tab === "quality" && <QualityTab quality={quality} />}
          {tab === "appraisal" && <AppraisalTab appraisal={appraisal} session={session} />}
          {tab === "env" && <EnvTab env={env} />}
          {tab === "closure" && <ClosureTab closure={closure} />}
        </PoCard>

        <PoCard span={12} kicker="Replay tooling" title="Reproduce the policy result locally"
              subtitle="The verifier rehashes inputs and recomputes the pass/fail decision over the pack on disk.">
          <PoCode label="$ verify policy">{`python3 scripts/verify_assurance_policy.py \\
  --policy   scripts/pqc_assurance_policy.json \\
  --ledger   <pack>/assurance_ledger.json \\
  --cbom     <pack>/pqc_cbom.cdx.json \\
  --attestation <pack>/pqc_attestation.intoto.json \\
  --output   <pack>/pqc_policy_result.json`}</PoCode>
          <PoCode label="$ replay-verify (full)">{`python3 scripts/verify_release_evidence_pack.py <pack> --tag <tag> --mode ${session.mode}`}</PoCode>
        </PoCard>
      </div>
    </>
  );
}

function PolicyTab({ policy }) {
  if (!policy) return <PoEmpty icon="○" title="Awaiting pqc_policy_result.json" hint="Produced by scripts/verify_assurance_policy.py." />;
  return (
    <div style={{ padding: 14 }}>
      {policy.failures.length > 0 ? (
        <PoCallout tone="err" title={`${policy.failures.length} policy failure(s)`}>
          <ul className="filelist">{policy.failures.map((f, i) => <li key={i} className="filelist__f filelist__f--wrap">{typeof f === "string" ? f : JSON.stringify(f)}</li>)}</ul>
        </PoCallout>
      ) : (
        <PoCallout tone="ok" title="No policy failures">All required policy gates are satisfied for this pack.</PoCallout>
      )}
      <PoHr />
      <PoSGrid>
        {Object.entries(policy.by_check_type || {}).map(([k, n]) => <PoStat key={k} k={k} v={n} />)}
      </PoSGrid>
      <PoHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Required attestation subjects</div>
      <div className="subjgrid">
        {Pop.POLICY.required_attestation_subjects.map(s => {
          const matched = (policy.checks || []).find(c => c.path === s || c.subject === s || c.id === s);
          return (
            <div key={s} className="subjrow">
              <span className="subjrow__f">{s}</span>
              <span className="subjrow__h">{matched?.sha256 ? <PoHash sha={matched.sha256} /> : "n/a"}</span>
              <PoTag tone={matched ? "ok" : "warn"}>{matched ? "verified" : "no entry"}</PoTag>
            </div>
          );
        })}
      </div>
      <PoHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Per-check results ({policy.checks.length})</div>
      <PoChecks items={policy.checks} max={120} />
    </div>
  );
}

function ProfileTab({ profile }) {
  if (!profile) return <PoEmpty icon="○" title="Awaiting pqc_assurance_profile_result.json" />;
  return (
    <div style={{ padding: 14 }}>
      <PoSGrid>
        <PoStat k="profile" v={profile.profile || "n/a"} />
        <PoStat k="checks" v={(profile.checks || []).length} />
        <PoStat k="failures" v={(profile.failures || []).length} />
        <PoStat k="passed" v={profile.passed ? "true" : "false"} />
      </PoSGrid>
      <PoHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Profile check results</div>
      <PoChecks items={profile.checks} max={200} />
    </div>
  );
}

function QualityTab({ quality }) {
  if (!quality) return <PoEmpty icon="○" title="Awaiting pqc_evidence_quality_result.json" />;
  const byClass = {};
  (quality.checks || []).forEach(c => {
    const k = c.evidence_class || "?";
    byClass[k] = (byClass[k] || 0) + 1;
  });
  return (
    <div style={{ padding: 14 }}>
      <PoSGrid>
        {Object.entries(byClass).map(([k, n]) => <PoStat key={k} k={k} v={n} />)}
      </PoSGrid>
      <PoHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Per-claim evidence class mapping ({quality.checks.length})</div>
      <PoChecks items={quality.checks} max={200} />
    </div>
  );
}

function AppraisalTab({ appraisal, session }) {
  if (!appraisal) return <PoEmpty icon="○" title="Awaiting pqc_appraisal_result.json"
    hint={`Produced when mode = ${session.mode} requires v7 appraisal evidence.`} />;
  return (
    <div style={{ padding: 14 }}>
      <PoSGrid>
        <PoStat k="mode" v={appraisal.mode || "n/a"} />
        <PoStat k="passed" v={appraisal.passed ? "true" : "false"} />
        <PoStat k="checks" v={(appraisal.checks || []).length} />
        <PoStat k="failures" v={(appraisal.failures || []).length} />
      </PoSGrid>
      <PoHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Required artifacts (per mode)</div>
      <div className="modereq">
        {(appraisal.checks || []).filter(c => c.check === "required_artifact").map((c, i) => (
          <div key={i} className="modereq__row">
            <PoSev level={c.passed ? "ok" : "err"} />
            <span className="modereq__f">{c.path}</span>
            <span className="modereq__v">{c.passed ? "present" : "missing"}</span>
            <PoTag tone={c.passed ? "ok" : "err"}>{c.passed ? "pass" : "fail"}</PoTag>
          </div>
        ))}
      </div>
      <PoHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Required claim evidence</div>
      <PoChecks items={(appraisal.checks || []).filter(c => c.check !== "required_artifact")} max={200} />
    </div>
  );
}

function EnvTab({ env }) {
  if (!env) return <PoEmpty icon="○" title="Awaiting pqc_environment_result.json" />;
  const deps = env.west_dependencies || {};
  return (
    <div style={{ padding: 14 }}>
      <div className="kv__k" style={{ marginBottom: 6 }}>West dependency pins</div>
      <div className="subjgrid">
        {Object.entries(deps).map(([name, rev]) => (
          <div key={name} className="subjrow">
            <span className="subjrow__f">{name}</span>
            <span className="subjrow__h"><PoHash sha={typeof rev === "string" ? rev : rev?.revision} /></span>
            <PoTag tone="ok">pinned</PoTag>
          </div>
        ))}
      </div>
      <PoHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Workflow environment</div>
      <div className="subjgrid">
        {Object.entries(env.workflow_environment || {}).map(([k, v]) => (
          <div key={k} className="subjrow">
            <span className="subjrow__f">{k}</span>
            <span className="subjrow__h mono">{typeof v === "object" ? JSON.stringify(v) : String(v)}</span>
            <PoTag tone="info">env</PoTag>
          </div>
        ))}
      </div>
      <PoHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Per-check results ({env.checks.length})</div>
      <PoChecks items={env.checks} max={200} />
    </div>
  );
}

function ClosureTab({ closure }) {
  if (!closure) return <PoEmpty icon="○" title="Awaiting pqc_claim_closure_result.json"
    hint="Produced by scripts/verify_pqc_claim_closure.py, checks that all artifacts the ledger claims to bind actually exist." />;
  return (
    <div style={{ padding: 14 }}>
      <PoSGrid>
        <PoStat k="closed claims" v={(closure.closed_claims || []).length} />
        <PoStat k="checks" v={(closure.checks || []).length} />
        <PoStat k="failures" v={(closure.failures || []).length} />
        <PoStat k="passed" v={closure.passed ? "true" : "false"} />
      </PoSGrid>
      <PoHr />
      <div className="kv__k" style={{ marginBottom: 6 }}>Closure checks</div>
      <PoChecks items={closure.checks} max={200} />
    </div>
  );
}

window.VIEW_POLICY = { PolicyView };
