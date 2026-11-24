// views-overview.jsx, Release Control Room.
// Real values from assurance_ledger.json, pqc_policy_result.json,
// pqc_reference_values.json, release-manifest, pqc_appraisal_result.json,
// firmware_assurance_status_result.json, device_evidence_token_result.json.

const { Card: OvCard, KV: OvKV, Tag: OvTag, Hr: OvHr, Sev: OvSev,
        Kpi: OvKpi, ThresholdBar: OvTBar, Callout: OvCallout, EvBind: OvEv,
        Code: OvCode, EmptyState: OvEmpty } = window.UI;
const { HashChip: OvHash, OriginChip: OvOrigin, EvBind2: OvEvBind2,
        DetailRow: OvDetail, StatGrid: OvSGrid, Stat: OvStat } = window.UIX;
const OvP = window.PQCP;
const OvS = window.STORE;

function OverviewView({ session, pack, onJumpView }) {
  const rel = OvS.release(pack);
  const lsum = OvS.ledgerSummary(pack);
  const policy = OvS.policyResult(pack);
  const appraisal = OvS.appraisalResult(pack);
  const refv = OvS.referenceValues(pack);
  const fw = OvS.firmwareStatus(pack);
  const tok = OvS.deviceEvidenceToken(pack);
  const env = OvS.environmentResult(pack);
  const profile = OvS.assuranceProfile(pack);
  const tm = OvS.transcriptManifest(pack);
  const cbom = OvS.cbomMeta(pack);
  const floor = OvS.cbomFloorState(pack, OvP.POLICY.required_cbom_components);
  const blockers = OvS.topBlockers(pack);

  const ingested = !!(pack && pack.loaded);
  const mode = OvP.MODES.modes.find(m => m.id === session.mode) || OvP.MODES.modes[2];

  if (!ingested) return <NoPackOverview onJumpView={onJumpView} />;

  // KPI tones
  const policyTone   = policy?.passed === true ? "ok" : policy?.passed === false ? "err" : "warn";
  const apprTone     = appraisal?.passed === true ? "ok" : appraisal?.passed === false ? "err" : "warn";
  const fwTone       = fw?.passed === true ? "ok" : fw?.passed === false ? "err" : "warn";
  const tokTone      = tok?.passed === true ? "ok" : tok?.passed === false ? "err" : "warn";
  const claimCovTone = lsum ? (lsum.fail === 0 ? "ok" : "err") : "warn";
  const cbomTone     = floor.missing.length === 0 && cbom ? "ok" : "warn";

  const claimCoverage = lsum ? lsum.pass / Math.max(1, lsum.total) : null;
  const floorCoverage = floor.floor_total ? floor.floor_present / floor.floor_total : null;

  return (
    <>
      {/* KPI row */}
      <div className="grid-kpi" style={{ marginBottom: 12 }}>
        <OvKpi
          label="Release"
          status={rel?.tag ? "info" : "warn"}
          value={rel?.tag || "n/a"}
          sub={rel?.head_sha
            ? <span className="mono">{String(rel.head_sha).slice(0,10)}{rel.dirty ? " · dirty" : " · clean"}</span>
            : "no release metadata"}
          evbind={<OvEvBind2 ev={OvS.evbind(pack, "assurance_ledger.json", "tag, head_sha")} compact />}
        />
        <OvKpi
          label="Policy"
          status={policyTone}
          value={policy ? (policy.passed ? "pass" : "fail") : "n/a"}
          sub={policy ? `${(policy.checks || []).length} checks · ${(policy.failures || []).length} failures` : "awaiting pqc_policy_result.json"}
          evbind={<OvEvBind2 ev={OvS.evbind(pack, "pqc_policy_result.json", "passed, failures[]")} compact />}
        />
        <OvKpi
          label="Claims"
          status={claimCovTone}
          value={lsum ? `${lsum.pass}/${lsum.total}` : "n/a"}
          sub={lsum ? <>{lsum.fail > 0 && <span style={{color:"var(--err)"}}>{lsum.fail} fail · </span>}{lsum.not_applicable} not-applicable</> : "awaiting assurance_ledger.json"}
          evbind={<OvEvBind2 ev={OvS.evbind(pack, "assurance_ledger.json", "claims[].status")} compact />}
        />
        <OvKpi
          label="CBOM floor"
          status={cbomTone}
          value={cbom ? `${floor.floor_present}/${floor.floor_total}` : "n/a"}
          sub={cbom ? `${cbom.component_count} components · ${floor.missing.length} missing` : "awaiting pqc_cbom.cdx.json"}
          evbind={<OvEvBind2 ev={OvS.evbind(pack, "pqc_cbom.cdx.json", "components[]")} compact />}
        />
        <OvKpi
          label="Mode appraisal"
          status={apprTone}
          value={appraisal ? (appraisal.passed ? "pass" : "fail") : "n/a"}
          sub={appraisal ? `mode: ${appraisal.mode || mode.id}` : `awaiting pqc_appraisal_result.json · ${mode.id}`}
          evbind={<OvEvBind2 ev={OvS.evbind(pack, "pqc_appraisal_result.json", "passed, mode")} compact />}
        />
      </div>

      <div className="grid grid-12">
        {/* Release facts + ref values */}
        <OvCard span={7} kicker="Release metadata" title={rel?.tag || "unreleased"}
              subtitle="Replayable identity binding from the assurance ledger, release manifest, and reference values."
              actions={<OvEvBind2 ev={rel?.evbind} />}>
          <div className="splitcols">
            <div>
              <OvDetail k="Project" v={rel?.project ? <span className="mono">{rel.project}</span> : null} />
              <OvDetail k="Version" v={rel?.version ? <span className="mono">{rel.version}</span> : null} />
              <OvDetail k="Tag" v={rel?.tag ? <span className="mono">{rel.tag}</span> : null} />
              <OvDetail k="HEAD" v={rel?.head_sha ? <OvHash sha={rel.head_sha} /> : null} />
              <OvDetail k="Tag → HEAD?" v={rel?.tag_points_to_head == null ? null : <OvTag tone={rel.tag_points_to_head ? "ok" : "warn"}>{rel.tag_points_to_head ? "matches" : "differs"}</OvTag>} />
              <OvDetail k="Working tree" v={rel?.dirty == null ? null : <OvTag tone={rel.dirty ? "warn" : "ok"}>{rel.dirty ? "dirty" : "clean"}</OvTag>} />
            </div>
            <div>
              <OvDetail k="Ledger schema" v={rel?.schema_version ? <span className="mono">v{rel.schema_version}</span> : null} />
              <OvDetail k="Generated" v={rel?.generated_at ? <span className="mono">{rel.generated_at}</span> : null} />
              <OvDetail k="Zephyr SDK" v={refv?.sdk_version ? <span className="mono">{refv.sdk_version}</span> : null} />
              <OvDetail k="Zephyr revision" v={refv?.zephyr_revision ? <OvHash sha={refv.zephyr_revision} /> : null} />
              <OvDetail k="Source remote" v={refv?.source_remote ? <span className="mono">{refv.source_remote}</span> : null} />
              <OvDetail k="Transcripts" v={refv?.transcript_count != null ? <span className="mono">{refv.transcript_count}</span> : null} />
            </div>
          </div>
          {refv?.west_dependencies && Object.keys(refv.west_dependencies).length > 0 && (
            <>
              <OvHr />
              <div className="kv__k" style={{ marginBottom: 6 }}>West dependency pins (reference values)</div>
              {Object.entries(refv.west_dependencies).map(([dep, rev]) => (
                <div key={dep} style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", fontSize: 11.5 }}>
                  <span className="mono">{dep}</span>
                  <OvHash sha={typeof rev === "string" ? rev : rev?.revision} />
                </div>
              ))}
            </>
          )}
        </OvCard>

        {/* Pack health */}
        <OvCard span={5} kicker="Pack health" title="Replay verification status"
              subtitle="Pass/fail rollup across the four enforcement layers: policy, profile, evidence quality, appraisal."
              actions={<OvEvBind2 ev={{ file: pack.source?.name || "(seed pack)", path: "pack.artifacts", env: "host_python", status: pack.loaded ? "present" : "missing" }} />}>
          <OvTBar
            label="Required claim coverage"
            value={claimCoverage}
            bands={[{ to: 0.7, tone: "err" }, { to: 0.95, tone: "warn" }, { to: 1, tone: "ok" }]}
            sub={lsum ? `${lsum.pass} pass · ${lsum.fail} fail · ${lsum.not_applicable} n/a` : "no ledger"} />
          <div style={{ height: 10 }} />
          <OvTBar
            label="CBOM floor coverage"
            value={floorCoverage}
            bands={[{ to: 0.5, tone: "err" }, { to: 1, tone: "ok" }]}
            sub={floor.missing.length === 0
              ? `${floor.floor_present}/${floor.floor_total} required components present`
              : `missing: ${floor.missing.join(", ")}`} />
          <OvHr />
          <OvSGrid>
            <OvStat k="Policy" v={policy ? (policy.passed ? "pass" : "fail") : "n/a"} s={`pqc_policy_result.json`} />
            <OvStat k="Profile" v={profile ? (profile.passed ? "pass" : "fail") : "n/a"} s={`pqc_assurance_profile_result.json`} />
            <OvStat k="Appraisal" v={appraisal ? (appraisal.passed ? "pass" : "fail") : "n/a"} s={`pqc_appraisal_result.json`} />
            <OvStat k="Firmware status" v={fw ? (fw.passed ? "pass" : "fail") : "n/a"} s={`firmware_assurance_status_result.json`} />
            <OvStat k="Device token" v={tok ? (tok.passed ? "pass" : "fail") : "n/a"} s={`device_evidence_token_result.json`} />
            <OvStat k="Environment" v={env ? (env.passed ? "pass" : "fail") : "n/a"} s={`pqc_environment_result.json`} />
          </OvSGrid>
        </OvCard>

        {/* Top blockers */}
        <OvCard span={7} kicker="Top blockers + warnings" title={blockers.length === 0 ? "No active blockers" : `${blockers.length} actionable item${blockers.length === 1 ? "" : "s"}`}
              subtitle="Derived from policy failures, claim failures, environment, and migration-readiness conditions."
              padded={false}>
          {blockers.length === 0 ? (
            <div style={{ padding: 18 }}>
              <OvCallout tone="ok">
                Every layer the pack covers is currently <strong>replay verified</strong>. Outstanding work would only be additive evidence (e.g. hardware runs) which is optional unless the active mode demands it.
              </OvCallout>
            </div>
          ) : (
            blockers.map(b => (
              <div key={b.id} className="finding">
                <OvSev level={b.severity} />
                <div>
                  <div className="finding__t">{b.title}</div>
                  <div className="finding__s">{b.sub}</div>
                </div>
                <span className="evb evb--warn" style={{ marginRight: 6 }}>
                  <span className="evb__sym">○</span>
                  <span className="evb__file">{b.file}</span>
                </span>
                <OvTag tone={b.severity === "high" ? "err" : "warn"}>{b.severity}</OvTag>
              </div>
            ))
          )}
        </OvCard>

        {/* Firmware digest + reference values summary */}
        <OvCard span={5} kicker="Firmware assurance digest" title="Hash-bound digest manifest"
              subtitle="Reference root expected from generated/pqcp_assurance_digest_generated.h"
              actions={<OvEvBind2 ev={refv?.evbind} compact />}>
          {refv ? (
            <>
              <OvDetail k="digest_root" v={refv.expected_firmware_digest_root ? <OvHash sha={refv.expected_firmware_digest_root} full /> : null} />
              <OvDetail k="artifact_count" v={refv.firmware_digest_artifact_count != null ? <span className="mono">{refv.firmware_digest_artifact_count}</span> : null} />
              <OvDetail k="cbom_components" v={refv.cbom_component_ids?.length ? <span className="mono">{refv.cbom_component_ids.length} ids</span> : null} />
              <OvDetail k="required_claims" v={refv.required_claim_ids?.length ? <span className="mono">{refv.required_claim_ids.length}</span> : null} />
              <OvDetail k="attestation subjects" v={refv.attestation_subject_count != null ? <span className="mono">{refv.attestation_subject_count}</span> : null} />
              <OvDetail k="policy_passed" v={refv.policy_passed == null ? null : <OvTag tone={refv.policy_passed ? "ok" : "err"}>{String(refv.policy_passed)}</OvTag>} />
              <OvDetail k="profile_passed" v={refv.profile_passed == null ? null : <OvTag tone={refv.profile_passed ? "ok" : "err"}>{String(refv.profile_passed)}</OvTag>} />
            </>
          ) : (
            <OvEmpty icon="○" title="No pqc_reference_values.json"
              hint="The pack does not yet contain replayable reference values. Regenerate with scripts/generate_pqc_reference_values.py." />
          )}
        </OvCard>

        {/* Replay command */}
        <OvCard span={12} kicker="Replay tooling" title="Reproduce this pack without rebuilding"
              subtitle="The console is read-only. Use these on a Python 3.12 host to re-hash every artifact and re-evaluate every claim.">
          <OvCode label="$ replay">{`python3 scripts/verify_release_evidence_pack.py \\
  ${pack.source?.mode === "directory" ? pack.source.name : "<release-pack-root>"} \\
  --tag ${rel?.tag || "<tag>"} \\
  --mode ${session.mode}`}</OvCode>
        </OvCard>
      </div>
    </>
  );
}

function NoPackOverview({ onJumpView }) {
  return (
    <div className="grid grid-12">
      <OvCard span={12} kicker="Release Control Room" title="No pack loaded"
            subtitle="Drop a pqcp_dashboard_seed_pack JSON, or point the console at a release output directory, to populate every metric on this page.">
        <OvCallout tone="info">
          Until a pack is ingested, every claim, hash, and benchmark row is marked <strong>awaiting</strong>.
          Nothing is invented. Use the Ingest tab to load the pack from <span className="mono">scripts/build_pqcp_dashboard_seed_pack.py</span> or any compatible producer.
        </OvCallout>
        <div style={{ marginTop: 16, display: "flex", gap: 8, alignItems: "center" }}>
          <button className="btn btn--primary" onClick={() => onJumpView?.("ingest")}>Go to Ingest</button>
          <span className="dim mono" style={{ fontSize: 11 }}>→ /scripts/build_pqcp_dashboard_seed_pack.py &lt;release-pack-root&gt; &gt; seedpack.json</span>
        </div>
      </OvCard>
    </div>
  );
}

window.VIEW_OVERVIEW = { OverviewView };
