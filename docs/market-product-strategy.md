# Market And Product Strategy

Status: repository-grounded product analysis for post-v1.0.0 `main`  
Analysis date: 2026-05-24  
Repository role: proprietary collaborative evaluation project  
Primary product question: how can `pqcp-zephyr-trust-stack` move from a
research-grade embedded PQC assurance prototype into a credible product
direction for external partners?

This document is intentionally specific to this repository. It does not treat
the project as a generic security startup, a generic crypto library, or a
generic compliance dashboard. The current repository is an out-of-tree Zephyr
module with ML-KEM and ML-DSA native backends, ACVP/KAT validation, benchmark
instrumentation, transcript hashing, release evidence packs, CBOM-style
inventory, policy replay, and partner-review artifacts. That is a strong base.
The product opportunity is not simply "ship PQC." The opportunity is to help
embedded teams prove what PQC firmware was built, validated, measured, and
released, without depending on a cloud CI account or a verbal assurance claim.

## Product Thesis

The most credible product direction is:

> A partner-reviewable embedded PQC validation and assurance package for Zephyr
> firmware teams, combining native ML-KEM/ML-DSA integration with local,
> replayable release evidence.

That framing matters. It avoids two weak positions:

- It should not be sold as a broad enterprise cryptography inventory platform.
  Those products already exist and focus on scanning fleets, certificates,
  TLS endpoints, source repositories, and key-management estates.
- It should not be sold as only a PQC primitive implementation. The strongest
  current repository value is the validation and evidence layer around
  embedded firmware integration, not just the primitive wrappers.

The product wedge is narrower and stronger:

- Zephyr-specific integration.
- Embedded/QEMU/local validation.
- Firmware-facing ACVP and KAT workflows.
- Reproducible release evidence.
- Policy replay over claims, hashes, transcripts, CBOM, benchmark provenance,
  profile decisions, and device evidence preparation.
- Native ML-KEM and ML-DSA provider discipline.

The customer should understand the product in one sentence:

> "This gives your embedded firmware team a PQC module plus a local evidence
> pack that proves which algorithms, builds, tests, benchmarks, and release
> claims were actually produced."

## Current Repository Product Surface

The product cannot be positioned honestly without separating implemented,
partial, and missing capabilities.

### Implemented Today

The following product-relevant capabilities exist in the repository now:

- Zephyr module structure:
  - `west.yml`
  - `zephyr/module.yml`
  - `Kconfig`
  - `CMakeLists.txt`
  - public headers under `include/pqcp_zephyr/`
- Native ML-KEM and ML-DSA integration:
  - `src/mlkem_zephyr.c`
  - `src/mldsa_zephyr.c`
  - `src/psa_mlkem_driver.c`
  - `src/psa_mldsa_driver.c`
  - pinned native backend dependencies in `west.yml`
- Embedded validation paths:
  - `tests/ztest_acvp_kat/`
  - `tests/ztest_acvp_serial/`
  - `tests/ztest_acvp_serial_negative/`
  - `tests/ztest_ct_smoke/`
  - `tests/ztest_tls_selftest/`
  - `tests/ztest_boot_kat_self_verify/`
- Serial ACVP command layer:
  - `src/acvp_cmd.c`
  - `include/pqcp_zephyr/acvp_cmd.h`
  - `samples/pqcp_serial_acvp/`
- Benchmark and cost-of-assurance tooling:
  - `scripts/run_benchmarks.py`
  - `scripts/run_benchmark_campaign.py`
  - `scripts/verify_benchmark_campaign.py`
  - `scripts/verify_benchmark_confidence.py`
  - `scripts/optimize_metric_campaign.py`
  - `scripts/run_extended_checks.py`
  - `scripts/resource_budgets.json`
  - `scripts/qemu_cost_of_assurance_regression.json`
- Release evidence pack generation:
  - `scripts/release_check.py`
  - `scripts/prepare_release_bundle.py`
  - `scripts/verify_release_evidence_pack.py`
  - `scripts/generate_assurance_ledger.py`
  - `scripts/render_assurance_report.py`
- Passport and policy artifacts:
  - `scripts/assurance_claims.json`
  - `scripts/pqc_assurance_policy.json`
  - `scripts/pqc_assurance_profile.json`
  - `scripts/pqc_evidence_quality.json`
  - `scripts/pqc_asset_trace_map.json`
  - `scripts/export_pqc_cbom.py`
  - `scripts/generate_pqc_attestation.py`
  - `scripts/generate_pqc_reference_values.py`
  - `scripts/generate_partner_review_scorecard.py`
- Product-readiness documentation:
  - `README.md`
  - `docs/release.md`
  - `docs/pqc-assurance-passport.md`
  - `docs/assurance-model.md`
  - `docs/performance-methodology.md`
  - `docs/api-overview.md`
  - `docs/maintainer-release-checklist.md`
  - `SECURITY.md`
  - `CONTRIBUTING.md`
  - `LICENSE`

This is enough to show a sophisticated technical proof-of-concept to embedded
security partners. It is not yet enough to call the package product-grade.

### Partially Implemented Today

The following are present but not mature enough for product claims:

- Hardware support:
  - `nucleo_h743zi` appears in resource and footprint workflows.
  - Current evidence is still mostly build-only or QEMU/local.
  - Physical execution, UART capture, energy measurement, and board-specific
    entropy validation are not yet complete product capabilities.
- Benchmark comparability:
  - Campaign tooling exists.
  - Some generated benchmark artifacts are still local regression evidence.
  - The repository needs repeated physical-board campaigns before it can make
    strong performance comparisons.
- Side-channel evidence:
  - CT smoke markers and instruction-policy checks exist.
  - They are explicitly smoke/regression evidence, not formal proof.
  - Product packaging must keep that wording precise.
- ACVP JSON interop:
  - Local JSON-to-serial tooling exists.
  - It is not a live ACVP service integration or certificate path.
- CBOM and attestation:
  - The repository emits CBOM-style and in-toto/SLSA-shaped artifacts.
  - The attestation is unsigned.
  - Product-grade trust requires a signing/key-custody story later.
- Consumer onboarding:
  - `west.yml`, README guidance, and `scripts/consumer_smoke.py` exist.
  - A real product needs a tested compatibility matrix across Zephyr releases,
    SDK versions, macOS/Linux hosts, and at least two hardware boards.
- Partner dashboard:
  - A UI/UX prototype exists outside the core validation path.
  - The repository needs a supported data contract before a dashboard can be
    sold as part of the product.

### Missing Today

The following are missing or not yet strong enough:

- Real hardware validation pack:
  - no mandatory hardware-run artifact in `release_check.py`;
  - no supported hardware transcript capture workflow with pass/fail history;
  - no product-level device evidence verification using a real nonce challenge.
- Release signing:
  - no signed attestation;
  - no signing key policy;
  - no offline/online key custody model;
  - no revocation process for bad evidence packs.
- Customer-ready support model:
  - no support tiers;
  - no response expectations for integration support;
  - no compatibility promise beyond current docs;
  - no upgrade policy for Zephyr and backend dependencies.
- Formal compliance positioning:
  - no FIPS 140-3 validation path;
  - no certified ACVP certificate integration;
  - no independent lab report;
  - no claim that QEMU evidence substitutes for physical evaluation.
- Product packaging:
  - no installable package or versioned binary distribution;
  - no customer-facing CLI naming/package boundary;
  - no license-key/offline entitlement story if commercialized;
  - no partner portal or stable dashboard ingestion schema.
- Scalability proof:
  - no evidence pack generated across dozens of boards/profiles;
  - no benchmark database with historical trend reports;
  - no multi-version upgrade replay across releases.

## Market Context

### Why This Market Exists

Post-quantum migration is no longer theoretical. NIST finalized ML-KEM in
FIPS 203, ML-DSA in FIPS 204, and SLH-DSA in FIPS 205. NIST NCCoE and CISA
guidance emphasize inventory, dependency discovery, migration planning,
interoperability, and readiness before cryptographically relevant quantum
computers exist. Enterprise teams are being told to find where cryptography is
used, classify it, plan migration, and prove change control.

Most of that guidance is enterprise-wide. Embedded firmware teams have a more
constrained problem:

- firmware is board-specific;
- toolchains and RTOS versions matter;
- memory budgets matter;
- serial validation matters;
- entropy sources differ by board;
- products may be offline, long-lived, or safety-critical;
- CI may not reproduce the same runtime conditions as a board;
- partners often want proof without being given unrestricted access to all
  internal infrastructure.

This repository sits exactly at that boundary: it is not trying to scan every
TLS endpoint in a corporation. It is trying to make embedded PQC firmware
reviewable.

### External Reference Points

The strategy should be aware of these external anchors:

- NIST FIPS 203, 204, and 205 define the standardized algorithm families that
  buyers will recognize.
- NIST NCCoE migration-to-PQC work frames inventory, prioritization, and staged
  migration as the operational problem.
- CISA quantum-readiness guidance pushes organizations toward dependency
  discovery and cryptographic migration planning.
- CycloneDX CBOM work is making cryptographic inventory a machine-readable
  supply-chain artifact.
- in-toto and SLSA provide provenance vocabulary that security teams already
  understand.
- IETF RATS provides vocabulary for evidence, appraisal, reference values, and
  attestation that can later map to device evidence.
- pqm4, SUPERCOP/eBACS, and OQS-style benchmarks set expectations for
  reproducible performance reporting and comparable metadata.

The repository already borrows from these ideas. The product opportunity is to
turn them into a practical embedded firmware review workflow.

## Target Users And Customer Segments

### Segment 1: Embedded Device OEM Security Teams

Examples:

- industrial IoT manufacturers;
- smart-meter and energy device vendors;
- gateway/router manufacturers;
- medical-device firmware teams;
- automotive ECU suppliers;
- defense/critical-infrastructure device teams.

Primary pain:

- "We need to start PQC migration, but our firmware is constrained and we need
  proof that a module actually builds, fits, runs, and rejects malformed input."

Why this repo matters:

- It speaks Zephyr.
- It includes QEMU and board-facing workflows.
- It produces evidence artifacts that a reviewer can inspect locally.
- It separates production-capable assets from validation/test-only assets.

What must exist before selling:

- at least one fully validated physical board release pack;
- a reproducible consumer workspace flow;
- a compatibility matrix;
- a hard statement of supported Zephyr and SDK versions;
- signed or at least tamper-evident release bundles;
- clear support policy.

### Segment 2: Semiconductor And Secure-Element Vendors

Examples:

- MCU vendors;
- secure element vendors;
- hardware security module vendors entering embedded PQC;
- silicon teams that want a Zephyr-facing demonstration layer.

Primary pain:

- "We need a credible firmware-level demo and validation harness that shows
  our platform can host PQC workflows and produce reviewable evidence."

Why this repo matters:

- It can act as a board bring-up and validation harness.
- ACVP serial flows can be adapted to board UARTs.
- Benchmark and resource budgets can show fit on constrained targets.
- Asset trace maps and policy replay make the demo more serious than a sample.

What must exist before selling:

- board adaptation guide;
- hardware benchmark capture workflow;
- entropy-source qualification checklist;
- hardware profile templates;
- clear boundaries between QEMU regression evidence and board evidence.

### Segment 3: Security Labs And Evaluation Partners

Examples:

- applied cryptography labs;
- firmware security consultancies;
- university/industry evaluation groups;
- product security assessors.

Primary pain:

- "We need a structured artifact to review, replay, and challenge, not a PDF
  that says everything passed."

Why this repo matters:

- The Passport model maps claims to artifacts and hashes.
- Negative scenarios are preserved by a compatibility floor.
- Tamper drills prove some replay relationships are enforced.
- The policy result creates a machine-readable appraisal target.

What must exist before selling:

- stable schema documentation;
- negative test suite coverage report;
- reproducibility scripts that do not assume the original developer machine;
- a way to ingest partner-provided transcripts;
- a red-team/adversarial validation mode.

### Segment 4: Enterprise Product-Security Teams With Embedded Fleets

Examples:

- energy utilities;
- logistics/industrial automation operators;
- telecom edge appliance teams;
- companies with large fleets of embedded gateways.

Primary pain:

- "We do not build every firmware component ourselves, but we need evidence
  that a supplier's PQC module is configured and validated correctly."

Why this repo matters:

- The evidence pack can become a supplier-review artifact.
- The CBOM-like output can connect firmware crypto inventory to enterprise
  crypto-inventory programs.
- Policy replay can turn a technical release into a procurement gate.

What must exist before selling:

- generated executive summary;
- schema-stable evidence package;
- offline verifier;
- partner dashboard or report viewer;
- compliance mapping to internal controls.

### Segment 5: Research And Standards-Oriented Collaborators

Examples:

- academics studying embedded PQC validation;
- standards-adjacent working groups;
- artifact-evaluation committees;
- government-funded migration pilots.

Primary pain:

- "We need reproducible, inspectable artifacts that connect implementations,
  tests, benchmarks, and policy decisions."

Why this repo matters:

- It already has an unusually rich evidence graph for an embedded PQC module.
- It has a path to publish artifact-evaluable experiments.

What must exist before using this as a paper artifact:

- physical-board benchmark campaigns;
- ablations of the evidence system;
- adversarial mutation results;
- comparison against simpler CI/SBOM-only baselines;
- independent reproduction instructions.

## Product Pain Points Solved

### Pain Point 1: "We implemented PQC, but nobody knows what was actually tested."

Repository answer:

- `scripts/assurance_claims.json` defines claims.
- `scripts/generate_assurance_ledger.py` creates claim results.
- `scripts/verify_release_evidence_pack.py` replay-checks the pack.

Product packaging:

- Make the Assurance Passport the customer-facing proof object.
- Provide a one-command offline verifier.
- Provide a human-readable report and a machine-readable JSON pack.

Still missing:

- stable schema versioning contract for customers;
- signed releases;
- product documentation that says which claims are mandatory by profile.

### Pain Point 2: "PQC benchmarks are hard to trust."

Repository answer:

- `scripts/run_benchmark_campaign.py` and `scripts/verify_benchmark_campaign.py`
  exist.
- `docs/performance-methodology.md` explains distributions and confidence.
- `benchmark_provenance.json` binds CSV bytes to metadata.

Product packaging:

- Ship a benchmark campaign template for each supported profile.
- Require board, clock, compiler, flags, backend family, repetitions, and
  transcript hash.
- Separate QEMU regression evidence from physical performance evidence.

Still missing:

- repeated physical benchmark results;
- energy and UART reliability metrics;
- external reference import examples with real published datasets;
- release notes that show performance trend across versions.

### Pain Point 3: "A supplier sent us an SBOM, but it does not prove behavior."

Repository answer:

- `scripts/export_pqc_cbom.py` creates crypto inventory.
- `scripts/generate_pqc_evidence_graph.py` links assets to claims and tests.
- `scripts/verify_provider_scope.py` and backend contract tools enforce source
  policy.

Product packaging:

- Position the CBOM as inventory, not proof by itself.
- Pair it with ledger, transcripts, policy result, and evidence graph.
- Provide a buyer-facing "asset to evidence" screen or report.

Still missing:

- schema validation against a pinned CBOM profile;
- customer-friendly CSV/HTML exports;
- integration guidance for enterprise GRC or supplier portals.

### Pain Point 4: "QEMU passed, but will this work on our board?"

Repository answer:

- QEMU/native workflows are strong.
- `nucleo_h743zi` footprint paths exist.
- hardware runner and promotion concepts exist.

Product packaging:

- Sell QEMU evidence as regression evidence.
- Sell hardware evidence only after board runs exist.
- Provide a board certification checklist: entropy, UART, timing, memory,
  stack, failure recovery, reboot behavior, release transcript capture.

Still missing:

- first-class physical board evidence root;
- automatic UART capture and hash binding;
- board support table with tested versions;
- reproducible hardware lab instructions.

### Pain Point 5: "We need a migration plan, not just code."

Repository answer:

- `scripts/pqc_assurance_profile.json` defines profiles.
- `scripts/generate_migration_readiness_report.py` emits migration readiness.
- `scripts/export_liboqs_inventory.py` tracks non-native experimental inventory.

Product packaging:

- Use profiles as customer maturity levels:
  - lab proof;
  - QEMU release evidence;
  - MCU build/footprint;
  - hardware review;
  - production candidate.
- Make each profile correspond to required evidence, not marketing labels.

Still missing:

- customer migration questionnaire;
- compatibility matrix by profile;
- integration plan for existing firmware products;
- lifecycle policy for backend and Zephyr upgrades.

## Competitors And Alternatives

This project does not compete cleanly with one category. It intersects several.

### Enterprise Crypto-Inventory And Migration Platforms

Examples in the market include platforms that discover cryptographic assets,
certificates, libraries, protocols, and migration exposure across enterprise
systems. Their value is breadth: scanning large estates and managing migration
programs.

Where they are stronger:

- enterprise-wide discovery;
- dashboards for CISOs and compliance teams;
- certificate/key lifecycle management;
- integration with asset inventories;
- governance workflows.

Where this repository can differentiate:

- firmware-level Zephyr build evidence;
- serial ACVP and KAT workflows on embedded targets;
- QEMU/local replay without cloud dependency;
- asset-to-source-to-test-to-hash traceability;
- board/profile-specific release packs.

Product stance:

- Do not compete head-on as an enterprise scanner.
- Integrate with those programs by exporting evidence, CBOM, and policy
  results that can be ingested by enterprise tools.

### General PQC Libraries And Provider Frameworks

Examples include broad PQC libraries and provider projects that expose many
algorithms or TLS integrations.

Where they are stronger:

- algorithm breadth;
- cryptographic implementation maturity;
- larger community testing;
- broader language/platform support.

Where this repository can differentiate:

- embedded Zephyr module packaging;
- native-provider discipline for ML-KEM/ML-DSA;
- release evidence and replay checks;
- ACVP/KAT/benchmark integration around firmware workflows;
- partner review artifacts.

Product stance:

- Do not position as "we have more algorithms."
- Position as "we make embedded PQC integration reviewable and repeatable."

### Zephyr Samples And Vendor SDK Examples

Vendor SDKs and examples often demonstrate a crypto operation or TLS handshake.

Where they are stronger:

- direct vendor board support;
- polished getting-started flow;
- integration with vendor IDEs and SDKs.

Where this repository can differentiate:

- evidence pack depth;
- negative-path preservation;
- benchmark and policy replay;
- independent local release gate;
- crypto asset traceability.

Product stance:

- Partner with board vendors or use their SDKs as targets.
- Package this as a validation layer above ordinary samples.

### Security Assessment And Compliance Consulting

Consultancies can manually review firmware and produce reports.

Where they are stronger:

- expert human analysis;
- certification pathway familiarity;
- side-channel lab capability;
- customer-specific threat modeling.

Where this repository can differentiate:

- reusable automation;
- lower-cost replay checks;
- standardized evidence artifacts;
- developer workflow integration.

Product stance:

- Sell to labs as tooling, not as a replacement for expert review.
- Use the project to make manual reviews faster and more reproducible.

## Differentiation

The strongest differentiation should be expressed as concrete capabilities:

1. Zephyr-native PQC integration:
   - Not a desktop-only crypto demo.
   - Uses Zephyr Kconfig, samples, ztests, west module metadata, and board
     build paths.

2. Evidence-first release workflow:
   - Release claims are represented as claim IDs.
   - Claims point to artifacts.
   - Artifacts are hashed.
   - Policies are replayed.
   - Tampering is tested.

3. Firmware validation surface:
   - KAT fixtures validate deterministic primitive behavior.
   - ACVP serial paths validate command/response behavior and negative cases.
   - CT smoke and instruction-policy checks catch narrow regression classes.
   - Benchmarks and resource budgets track fit and overhead.

4. Local/offline review:
   - A reviewer can inspect a pack without depending on GitHub Actions.
   - This matters for restricted partner environments and proprietary review.

5. Provider discipline:
   - ML-KEM and ML-DSA implementation source policy is explicit and executable.
   - Experimental/non-native scheme inventory is separated from production
     profiles.

6. Embedded migration readiness:
   - Profiles, evidence quality, migration readiness, and device digest
     artifacts create a path from lab proof to hardware review.

The product should avoid weaker claims:

- Do not claim certification.
- Do not claim formal constant-time proof.
- Do not claim QEMU numbers are hardware performance.
- Do not claim full enterprise cryptography discovery.
- Do not claim production readiness for every supported sample.

## Deployment Scenarios

### Scenario A: Partner Review Pack For A Firmware Release

Workflow:

1. Firmware team runs:
   - `python3 scripts/release_check.py --tag <tag> --output-root <dir>`
2. Team sends the output directory to a partner.
3. Partner runs:
   - `python3 scripts/verify_release_evidence_pack.py <dir> --tag <tag>`
4. Partner inspects:
   - `assurance_report.html`
   - `partner_review_scorecard.md`
   - `pqc_cbom.cdx.json`
   - `pqc_policy_result.json`
   - `benchmark_campaign_result.json`

Product value:

- converts "trust us" into "replay these checks."

Repository gaps:

- signed pack;
- stable customer verifier package;
- documented schema support window.

### Scenario B: Board Bring-Up For A New Zephyr Target

Workflow:

1. Customer adds board overlay.
2. Runs consumer smoke:
   - `scripts/consumer_smoke.py`
3. Runs ACVP serial sample on UART.
4. Captures transcript.
5. Runs hardware benchmark campaign.
6. Imports board evidence into Passport.

Product value:

- shows whether PQC fits and behaves on a real board.

Repository gaps:

- UART capture tool as a first-class product command;
- hardware evidence schema;
- board support matrix;
- entropy-source validation.

### Scenario C: Supplier Evidence Intake

Workflow:

1. Supplier sends Passport pack.
2. Buyer runs offline verifier.
3. Buyer checks policy result and scorecard.
4. Buyer maps CBOM assets to internal crypto migration inventory.

Product value:

- gives buyers machine-readable evidence instead of a PDF-only attestation.

Repository gaps:

- enterprise-friendly export formats;
- mapping template to CISA/NIST migration fields;
- customer policy customization guide.

### Scenario D: Internal PQC Migration Pilot

Workflow:

1. Security team selects a gateway/firmware target.
2. Runs lab profile.
3. Runs QEMU release profile.
4. Moves to MCU footprint profile.
5. Promotes to hardware review profile.

Product value:

- turns migration into staged evidence thresholds.

Repository gaps:

- readiness questionnaire;
- project plan templates;
- profile pass/fail dashboard;
- upgrade tracking between releases.

### Scenario E: Research Artifact Evaluation

Workflow:

1. Reviewer clones repo.
2. Runs deterministic tests.
3. Replays provided evidence pack.
4. Runs mutation/tamper drills.
5. Compares benchmark campaign outputs.

Product value:

- makes a paper artifact concrete and inspectable.

Repository gaps:

- public artifact-evaluation script;
- reduced-time reproduction mode;
- curated external comparison datasets;
- artifact appendix.

## Pricing And Packaging Possibilities

Pricing cannot be finalized without customer interviews, but packaging can be
made concrete now.

### Package 1: Proprietary Evaluation Kit

Audience:

- external collaborators;
- labs;
- early design partners.

Includes:

- repository access;
- local release/check scripts;
- QEMU evidence generation;
- docs and onboarding;
- limited support.

Best use:

- pre-commercial partner validation.

What must exist:

- clean README;
- SECURITY.md;
- CONTRIBUTING.md;
- release verification checklist;
- reproducible local pack.

Current status:

- mostly implemented.

### Package 2: Embedded PQC Assurance Toolkit

Audience:

- firmware security teams and embedded OEMs.

Includes:

- Zephyr module;
- ACVP/KAT test harnesses;
- release pack generator;
- offline verifier;
- benchmark campaign tooling;
- board support templates.

Possible pricing:

- annual engineering license per organization;
- paid support for additional boards;
- paid evidence-pack review service.

What must exist:

- stable CLI package;
- documented supported targets;
- physical board evidence;
- compatibility matrix;
- schema support policy.

Current status:

- partially implemented.

### Package 3: Partner Review Dashboard

Audience:

- suppliers, buyers, labs, internal security review boards.

Includes:

- local dashboard reading release pack JSON;
- claim explorer;
- CBOM view;
- benchmark and profile views;
- policy failure drill-down;
- exportable report.

Possible pricing:

- per-seat review tool;
- bundled with toolkit;
- partner portal later.

What must exist:

- stable JSON data contract;
- sample packs;
- no invented values in UI;
- offline mode;
- strict "QEMU vs hardware" labels.

Current status:

- prototype only.

### Package 4: Board Enablement Service

Audience:

- MCU vendors and embedded product teams.

Includes:

- porting to customer board;
- entropy integration review;
- hardware benchmark campaign;
- ACVP serial capture;
- release evidence pack for board profile.

Possible pricing:

- fixed-fee board bring-up;
- recurring support retainer;
- premium for side-channel lab partnership coordination.

What must exist:

- board bring-up checklist;
- repeatable UART capture;
- hardware lab scripts;
- support contract.

Current status:

- roadmap item.

### Package 5: Evidence Review Service

Audience:

- buyers evaluating supplier firmware.

Includes:

- run verifier against supplier pack;
- inspect CBOM and policy result;
- produce short review memo;
- identify missing evidence.

Possible pricing:

- per-pack review;
- annual supplier review program;
- bundled advisory service.

What must exist:

- review checklist;
- report template;
- clear non-certification disclaimer;
- severity taxonomy.

Current status:

- feasible after scorecard/report maturity.

## Minimum Viable Product Requirements

The MVP should not attempt to solve every PQC migration problem. A credible
MVP should be:

> A Zephyr PQC assurance toolkit for ML-KEM/ML-DSA firmware releases, with one
> supported physical board profile, a local evidence pack, and an offline
> verifier.

### MVP Must-Haves

1. Supported platform matrix:
   - Zephyr version;
   - Zephyr SDK version;
   - host OS versions;
   - `qemu_x86_64`;
   - `native_sim`;
   - one physical MCU board.

2. One-command local release evidence:
   - `scripts/release_check.py --tag <tag> --output-root <dir>`
   - deterministic output layout;
   - no generated artifacts committed by accident.

3. Offline replay verifier:
   - validates hashes;
   - validates claims;
   - validates CBOM/provider scope;
   - validates benchmark provenance;
   - validates transcript manifest;
   - validates policy result.

4. Physical board evidence lane:
   - build;
   - flash/run instructions;
   - UART transcript capture;
   - benchmark campaign;
   - ACVP serial recovery;
   - entropy-source notes.

5. Clear product boundaries:
   - not certification;
   - not formal side-channel proof;
   - not enterprise-wide scanning;
   - not production-ready for every board.

6. Partner-readable outputs:
   - HTML report;
   - Markdown scorecard;
   - JSON evidence pack;
   - CBOM;
   - release manifest.

7. Security process:
   - private vulnerability reporting;
   - version support policy;
   - changelog;
   - patch release plan.

8. Customer onboarding:
   - fresh west init;
   - sample build;
   - basic ACVP command;
   - verifier walkthrough;
   - known limitations.

### MVP Should-Haves

1. Dashboard reading local pack JSON.
2. Customer policy customization file.
3. External benchmark import with metadata validation.
4. Evidence tamper drill report.
5. Hardware absence handling that is explicit, not silent.
6. Release bundle signing roadmap.

### MVP Should Not Include Yet

1. Broad enterprise cryptography scanning.
2. Claims of certification.
3. Production use of experimental provider paths.
4. Automated claims for physical side-channel security.
5. Unsupported board claims.

## Engineering Features Needed Before Product-Grade Presentation

### Feature 1: Stable Evidence Pack Contract

Current state:

- `verify_release_evidence_pack.py` checks many artifacts.
- Schema versions exist across claims, policy, profile, quality, and Passport
  outputs.

Missing:

- a customer-facing schema contract document;
- compatibility promise for schema v7;
- migration rules for old packs;
- JSON schema files for key artifacts.

Implementation:

- Add `schemas/` directory:
  - `schemas/assurance_ledger.schema.json`
  - `schemas/pqc_cbom_profile.schema.json`
  - `schemas/pqc_policy_result.schema.json`
  - `schemas/partner_scorecard.schema.json`
  - `schemas/release_manifest.schema.json`
- Add `scripts/validate_evidence_schemas.py`.
- Wire it into full local `release_check.py`.
- Add tests under `scripts/test_evidence_schemas.py`.

Product impact:

- customers can build tools against stable artifacts without reverse
  engineering scripts.

### Feature 2: Physical Board Evidence Pack

Current state:

- QEMU and native simulator paths are strong.
- MCU footprint data exists.
- Hardware benchmark helper concepts exist.

Missing:

- required physical-board profile;
- UART transcript capture as a first-class script;
- board evidence result JSON;
- board profile scorecard.

Implementation:

- Add `scripts/run_board_evidence_capture.py`.
- Add `scripts/verify_board_evidence.py`.
- Add `scripts/board_profiles.json`.
- Output:
  - `board_evidence_result.json`
  - `board_uart_transcript.log`
  - `board_benchmark_campaign_result.json`
  - `board_entropy_result.json`
- Add documentation:
  - `docs/board-validation.md`

Product impact:

- makes hardware claims credible.

### Feature 3: Signed Evidence Bundle

Current state:

- hashes and replay checks exist.
- attestation is unsigned.

Missing:

- key custody;
- signing command;
- signature verification;
- revocation guidance.

Implementation:

- Add `scripts/sign_release_evidence_pack.py`.
- Add `scripts/verify_release_evidence_signature.py`.
- Add `docs/signing-policy.md`.
- Support detached signatures over a canonical pack manifest.
- Keep signing optional until custody is decided.

Product impact:

- moves from "tamper-evident on disk" to "publisher-authenticated."

### Feature 4: Customer Policy Profiles

Current state:

- `scripts/pqc_assurance_policy.json`
- `scripts/pqc_assurance_profile.json`
- `scripts/pqc_appraisal_policy.json`

Missing:

- customer override mechanism;
- policy-diff report;
- strict explanation of allowed not-applicable cases.

Implementation:

- Add `scripts/merge_customer_policy.py`.
- Add `docs/customer-policy-profiles.md`.
- Add output:
  - `customer_policy_diff.json`
  - `customer_policy_result.json`

Product impact:

- lets different customers express acceptance criteria without modifying repo
  internals.

### Feature 5: Board And Version Compatibility Matrix

Current state:

- README lists supported targets.
- CI and scripts imply supported versions.

Missing:

- versioned matrix with pass/fail history;
- known issue entries;
- deprecation policy.

Implementation:

- Add `docs/compatibility-matrix.md`.
- Add `scripts/update_compatibility_matrix.py`.
- Pull outputs from release pack:
  - Zephyr revision;
  - SDK version;
  - board;
  - profile;
  - pass/fail;
  - evidence pack hash.

Product impact:

- gives buyers a concrete support boundary.

### Feature 6: Evidence Dashboard With Real Data Contract

Current state:

- dashboard prototype exists outside core validation.
- release pack JSON exists.

Missing:

- production data loader;
- schema validation;
- offline bundle mode;
- no invented values;
- accessibility and export review.

Implementation:

- Add `ui/assurance-dashboard/` only if it becomes supported.
- Read local pack files:
  - `assurance_ledger.json`
  - `pqc_cbom.cdx.json`
  - `pqc_policy_result.json`
  - `partner_review_scorecard.json`
  - `benchmark_campaign_result.json`
  - `pqc_migration_readiness.json`
- Add sample pack fixtures.
- Add Playwright smoke tests.

Product impact:

- makes the product understandable to non-script users.

### Feature 7: Productized CLI

Current state:

- many scripts exist.
- scripts are powerful but fragmented.

Missing:

- one CLI entry point;
- stable command names;
- friendly errors;
- help output designed for customers.

Implementation:

- Add `scripts/pqcp_tool.py` or package module:
  - `pqcp release build-pack`
  - `pqcp release verify-pack`
  - `pqcp board capture`
  - `pqcp policy replay`
  - `pqcp benchmark campaign`
  - `pqcp evidence dashboard-export`
- Keep old scripts as internal implementation.

Product impact:

- reduces onboarding friction and support load.

## Go-To-Market Strategy

### Phase 1: Design Partner Evaluation

Goal:

- validate that embedded teams value replayable PQC evidence enough to adopt
  the workflow.

Target partners:

- one embedded OEM;
- one MCU/board vendor;
- one security lab or university group.

Offer:

- proprietary evaluation access;
- onboarding session;
- one board/profile evidence pack;
- partner feedback loop.

Success criteria:

- partner can run verifier without help;
- partner can explain the Passport outputs;
- partner identifies at least one real integration requirement;
- partner agrees the evidence pack is more useful than a PDF-only report.

Repository work before Phase 1:

- finish compatibility matrix;
- produce one golden sample release pack;
- add customer walkthrough;
- ensure `release_check.py --ci` remains fast;
- keep full local release stable.

### Phase 2: Board Evidence Pilot

Goal:

- prove the workflow on real hardware, not only QEMU.

Target partners:

- MCU vendor or firmware team with `nucleo_h743zi`-class board.

Offer:

- hardware evidence capture;
- UART transcript hash binding;
- benchmark campaign;
- board profile report.

Success criteria:

- physical board pack passes offline replay;
- board benchmark results include repetitions and metadata;
- ACVP serial recovery works on UART;
- entropy-source assumptions are documented.

Repository work before Phase 2:

- board capture scripts;
- hardware benchmark profile;
- board validation doc;
- entropy checklist.

### Phase 3: Commercial Toolkit Trial

Goal:

- package the repo as a supported evaluation toolkit.

Target partners:

- 3-5 embedded/security teams.

Offer:

- license terms;
- supported release;
- private support channel;
- dashboard preview;
- evidence review service option.

Success criteria:

- customer runs pack generation independently;
- customer asks for board/profile extension rather than basic explanation;
- evidence pack appears in their internal review process.

Repository work before Phase 3:

- productized CLI;
- versioned schema docs;
- support policy;
- signed evidence pack option;
- polished dashboard or report viewer.

### Phase 4: Product Release Candidate

Goal:

- freeze MVP capability and support boundaries.

Offer:

- supported Zephyr baseline;
- supported boards;
- supported evidence schema;
- release cadence;
- support tiers.

Success criteria:

- clean install;
- clean verify;
- hardware pack available;
- no overclaims;
- clear paid value.

Repository work before Phase 4:

- CI green and local release green;
- reproducible release bundle;
- published product docs;
- customer onboarding videos or guide;
- security patch process tested.

## Product Risks

### Risk 1: Overclaiming Certification

Problem:

- Buyers may interpret "ACVP", "attestation", "CBOM", or "Passport" as formal
  certification.

Mitigation:

- Docs must say "local replay evidence" and "not certification."
- Dashboard must label QEMU/local-only results.
- ACVP JSON interop must be described as workflow compatibility, not certified
  validation.

Repository changes:

- Add claim-boundary checks in docs tests.
- Extend `scripts/test_research_product_dossier.py` style checks to product
  docs.

### Risk 2: Hardware Evidence Gap

Problem:

- Product buyers care about physical boards.

Mitigation:

- Make board evidence the next product milestone.
- Never present QEMU as physical performance.

Repository changes:

- `scripts/run_board_evidence_capture.py`
- `docs/board-validation.md`
- `scripts/verify_board_evidence.py`

### Risk 3: Tooling Complexity

Problem:

- The repo has many scripts. A customer may not know which command matters.

Mitigation:

- Productize commands behind one CLI.
- Keep lower-level scripts for maintainers.

Repository changes:

- `scripts/pqcp_tool.py`
- CLI documentation.

### Risk 4: Evidence Schema Drift

Problem:

- If JSON shapes drift, dashboards and partner workflows break.

Mitigation:

- Add JSON schemas.
- Add compatibility tests.
- Version evidence packs explicitly.

Repository changes:

- `schemas/`
- `scripts/validate_evidence_schemas.py`

### Risk 5: Backend And Dependency Drift

Problem:

- PQC backends and Zephyr move quickly.

Mitigation:

- Keep backend currency tools.
- Add upgrade evaluation reports.
- Maintain compatibility matrix.

Repository changes:

- strengthen `scripts/evaluate_backend_update.py`.
- publish `docs/backend-upgrade-policy.md`.

### Risk 6: Security Liability

Problem:

- Customers may assume the module is safe for production just because tests
  pass.

Mitigation:

- Keep security boundaries explicit.
- Provide deployment checklists.
- Require platform-specific entropy and side-channel review.

Repository changes:

- `docs/deployment-security-checklist.md`
- profile-level production gates.

### Risk 7: Proprietary Collaboration Friction

Problem:

- Some partners prefer open-source dependencies or need license review.

Mitigation:

- Keep licensing clear.
- Provide collaborator-friendly review package.
- Explain what rights are and are not granted.

Repository changes:

- maintain `LICENSE`, `CONTRIBUTING.md`, and `SECURITY.md`.
- add `docs/partner-evaluation-guide.md`.

## Product Metrics

The project should track product metrics that match its value proposition.

### Technical Adoption Metrics

- time from clone to first successful `consumer_smoke.py`;
- time from clone to first verified evidence pack;
- number of supported Zephyr/SDK combinations;
- number of supported board profiles;
- evidence pack verification time;
- release pack size;
- dashboard load time for a pack;
- number of schema-breaking changes per release.

### Evidence Quality Metrics

- required claims passing by profile;
- not-applicable claims by reason;
- number of artifacts with SHA-256 binding;
- number of transcripts captured;
- number of tamper-drill cases detected;
- number of hardware-backed claims;
- benchmark campaign sample count;
- CT smoke sample count and pass/fail trend.

### Customer Outcome Metrics

- number of partner packs replayed without maintainer help;
- number of customer boards onboarded;
- number of policy customizations supported;
- number of evidence gaps found before partner delivery;
- reduction in manual review time.

## Product Roadmap

### Milestone 0: Current Prototype State

Status:

- completed as engineering prototype.

Capabilities:

- Zephyr module;
- native backend integration;
- ACVP/KAT/ztest workflows;
- local release evidence pack;
- Passport/appraisal tooling;
- product-readiness docs.

Limitations:

- no supported physical board evidence pack;
- no signed release evidence;
- fragmented script interface;
- schema contract not productized.

### Milestone 1: Evidence Pack MVP

Goal:

- make the local pack stable enough for design partners.

Required repository work:

- add evidence schema docs and validation;
- create sample golden pack;
- add partner evaluation guide;
- add one command for pack generation and verification;
- improve scorecard clarity.

Expected outputs:

- `schemas/*.schema.json`
- `docs/partner-evaluation-guide.md`
- `scripts/pqcp_tool.py`
- `examples/evidence-pack-manifest.md`

### Milestone 2: Board Evidence MVP

Goal:

- prove one real board path.

Required repository work:

- board capture script;
- board profile config;
- UART transcript binding;
- hardware benchmark campaign;
- board evidence verifier.

Expected outputs:

- `board_evidence_result.json`
- `board_uart_transcript.log`
- `board_benchmark_campaign_result.json`
- `docs/board-validation.md`

### Milestone 3: Partner Dashboard MVP

Goal:

- make evidence understandable without reading JSON manually.

Required repository work:

- stable UI data contract;
- dashboard loading local pack;
- finding drill-down;
- clear QEMU/hardware labels;
- report export.

Expected outputs:

- `ui/assurance-dashboard/`
- `docs/dashboard-data-contract.md`
- UI tests.

### Milestone 4: Signed Evidence And Support Policy

Goal:

- make evidence publisher-authenticated and supportable.

Required repository work:

- signing policy;
- detached signatures;
- verification command;
- support/deprecation matrix;
- release cadence.

Expected outputs:

- `docs/signing-policy.md`
- `scripts/sign_release_evidence_pack.py`
- `scripts/verify_release_evidence_signature.py`
- `docs/support-policy.md`

### Milestone 5: Commercial Evaluation Kit

Goal:

- make product trial repeatable.

Required repository work:

- polished onboarding;
- board evidence;
- dashboard;
- product CLI;
- sample packs;
- support docs.

Expected outputs:

- versioned evaluation kit;
- customer quickstart;
- design-partner feedback loop.

## What A Product Demo Should Show

A strong product demo should not start with code. It should start with a
reviewer problem:

1. "Here is a firmware release claim."
2. "Here is the build and validation evidence."
3. "Here is the crypto inventory."
4. "Here is the policy decision."
5. "Here is the replay command."
6. "Here is how tampering is detected."
7. "Here is what is QEMU-only and what is hardware-backed."

Recommended demo flow:

1. Show README one-sentence purpose.
2. Run or show:
   - `python3 scripts/verify_release_evidence_pack.py <pack> --tag <tag>`
3. Open:
   - `partner_review_scorecard.md`
4. Show one claim:
   - asset -> source -> test -> transcript -> artifact -> hash -> policy.
5. Show CBOM inventory.
6. Show benchmark campaign with QEMU label.
7. Show missing hardware validation explicitly as next milestone.

This is more credible than showing algorithm calls first.

## Sales Narrative

The strongest sales narrative is:

> Embedded PQC migration is not just choosing algorithms. A product team must
> prove the firmware built, the vectors passed, malformed inputs were rejected,
> benchmarks were captured with provenance, and release artifacts were not
> changed after validation. This toolkit packages those checks into a local
> evidence workflow for Zephyr firmware.

Avoid:

- "We solve all PQC migration."
- "This is certified."
- "This proves constant-time behavior."
- "This replaces security review."
- "This is production-ready for every board."

Use:

- "local replay evidence";
- "firmware release review";
- "Zephyr integration";
- "claim-to-artifact traceability";
- "QEMU regression evidence";
- "hardware promotion path";
- "partner-review pack."

## Buyer Objections And Answers

### "Why not just use an existing PQC library?"

Answer:

- Existing libraries provide primitives and sometimes protocol integrations.
  This project focuses on embedded Zephyr release evidence: KAT/ACVP paths,
  benchmarks, resource budgets, CBOM, policy replay, and transcript hashing.
  It can complement an enterprise PQC library strategy rather than replace it.

### "Is this certified?"

Answer:

- No. It is not a certification. It is a local replayable evidence package.
  Certification would require a separate lab/process path.

### "Can we trust QEMU numbers?"

Answer:

- QEMU numbers are regression evidence. They are useful for detecting drift
  and comparing local builds under controlled conditions. Product performance
  claims require physical board campaigns.

### "Can we use this in production?"

Answer:

- The repository has production-oriented components, but product deployment
  requires board-specific entropy, key storage, side-channel review, memory
  budget validation, and a supported release profile.

### "What is the business value?"

Answer:

- It reduces review friction. Instead of sending a claim that PQC was added,
  a firmware team can send a pack that shows what was built, tested, measured,
  inventoried, and replay-verified.

### "What makes this different from an SBOM?"

Answer:

- An SBOM/CBOM tells what is present. This project links inventory to tests,
  transcripts, hashes, policies, benchmarks, and release metadata.

### "What if our policy differs?"

Answer:

- The current policy system can become customer-configurable. The product
  roadmap should add policy overlays and policy-diff reports.

## Engineering-To-Product Mapping

| Product claim | Current repository basis | Product-grade requirement |
| --- | --- | --- |
| Zephyr PQC module | `west.yml`, `Kconfig`, `CMakeLists.txt`, `include/`, `src/` | compatibility matrix and support policy |
| Native ML-KEM/ML-DSA backend discipline | backend contract and currency scripts | release-pack provider attestation with upgrade policy |
| KAT validation | `tests/ztest_acvp_kat/`, KAT provenance script | per-release KAT report with schema-stable output |
| ACVP serial validation | `src/acvp_cmd.c`, serial ztests | hardware UART transcript capture |
| Benchmark evidence | benchmark campaign scripts | physical board campaign and external comparison imports |
| Resource budgets | `scripts/resource_budgets.json` | board-specific measured budgets |
| CT smoke evidence | CT ztest and analysis scripts | physical side-channel lab path and strong disclaimers |
| CBOM inventory | `export_pqc_cbom.py` | schema validation and customer export |
| Assurance Passport | release check and pack verifier | signed pack and stable customer CLI |
| Consumer onboarding | README and consumer smoke script | tested clean-workspace install matrix |
| Partner review | scorecard and report scripts | dashboard and review guide |

## Minimum Product Documentation Set

Before the project is presented as product-grade, the docs should include:

- `docs/product-overview.md`
  - what the product is and is not.
- `docs/partner-evaluation-guide.md`
  - how a partner reviews a pack.
- `docs/compatibility-matrix.md`
  - Zephyr, SDK, host OS, board, profile, status.
- `docs/board-validation.md`
  - hardware capture steps.
- `docs/evidence-schema.md`
  - stable artifact data contract.
- `docs/support-policy.md`
  - version support and response expectations.
- `docs/signing-policy.md`
  - future release pack signing.
- `docs/customer-policy-profiles.md`
  - how customers can customize acceptance policy.

## Positioning For A Website Or Partner Deck

### Short Description

`pqcp-zephyr-trust-stack` is a Zephyr-focused PQC validation and assurance
toolkit for embedded firmware teams. It combines native ML-KEM/ML-DSA
integration with local release evidence: KAT/ACVP validation, benchmark
provenance, crypto inventory, transcript hashing, policy replay, and offline
verification.

### Three Pillars

1. Build:
   - Zephyr module, native providers, public APIs, samples.
2. Validate:
   - KAT, ACVP serial, negative cases, CT smoke, benchmarks, resource budgets.
3. Prove:
   - ledger, CBOM, attestation-shaped metadata, hashes, policy result, replay.

### One-Line Differentiator

Most PQC tooling helps select or implement algorithms; this project helps an
embedded team prove what PQC firmware release evidence exists.

### Product Boundary

This is not a certification claim and not a complete enterprise cryptography
scanner. It is a local embedded firmware evidence workflow with a hardware
promotion path.

## Partner Pilot Plan

### Week 1: Onboarding

- Partner receives repository access.
- Partner runs consumer smoke.
- Partner verifies provided sample pack.
- Partner identifies target board/profile.

Deliverables:

- onboarding report;
- list of environment issues;
- initial product friction notes.

### Week 2: Evidence Pack

- Generate local QEMU release pack.
- Replay verify pack.
- Review CBOM and policy result.
- Walk through scorecard.

Deliverables:

- verified evidence pack;
- policy gap report.

### Week 3: Board Promotion

- Build target board.
- Capture UART transcript.
- Run benchmark/ACVP subset.
- Record hardware limitations.

Deliverables:

- board evidence report;
- compatibility matrix entry.

### Week 4: Product Feedback

- Partner reviews dashboard/report.
- Partner ranks missing capabilities.
- Decide whether to proceed to supported evaluation kit.

Deliverables:

- product roadmap feedback;
- support requirements;
- commercial next-step proposal.

## Product Readiness Classification

As of this audit:

- Research prototype:
  - yes, strong.
- Local assurance prototype:
  - yes, strong.
- Partner evaluation kit:
  - close, but needs schema/support/onboarding polish.
- Product MVP:
  - not yet.
- Hardware-validated product:
  - not yet.
- Certified product:
  - no.
- Enterprise crypto migration platform:
  - no, and should not be the initial target.

## Recommended Next Three Product Patches

### Patch 1: Evidence Schema Contract

Add:

- `schemas/`
- `scripts/validate_evidence_schemas.py`
- `docs/evidence-schema.md`
- tests for generated pack artifacts.

Why:

- product dashboards, customer tooling, and partner workflows need stable data
  contracts.

### Patch 2: Partner Evaluation Guide And Golden Pack

Add:

- `docs/partner-evaluation-guide.md`
- `docs/product-overview.md`
- sample pack manifest without committing huge generated artifacts;
- scripted smoke verifier for a provided pack.

Why:

- customers need to understand what to do in the first hour.

### Patch 3: Board Evidence Capture

Add:

- `scripts/run_board_evidence_capture.py`
- `scripts/verify_board_evidence.py`
- `docs/board-validation.md`
- board profile result JSON.

Why:

- product credibility requires physical evidence, not only QEMU.

## External Sources For Market And Standards Context

- NIST FIPS 203, ML-KEM:
  https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204, ML-DSA:
  https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205, SLH-DSA:
  https://csrc.nist.gov/pubs/fips/205/final
- NIST NCCoE Migration to Post-Quantum Cryptography:
  https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc
- CISA Quantum Readiness:
  https://www.cisa.gov/quantum
- CycloneDX CBOM / cryptographic inventory context:
  https://cyclonedx.org/
- in-toto Attestation Framework:
  https://github.com/in-toto/attestation
- SLSA provenance:
  https://slsa.dev/spec/v1.0/provenance
- IETF RATS architecture, RFC 9334:
  https://www.rfc-editor.org/rfc/rfc9334.html
- Open Quantum Safe algorithm inventory:
  https://openquantumsafe.org/liboqs/algorithms/
- pqm4 embedded PQC benchmarking:
  https://github.com/mupq/pqm4
- SUPERCOP/eBACS benchmarking:
  https://bench.cr.yp.to/supercop.html

## Final Product Direction

The product should be pushed as a focused embedded PQC assurance toolkit, not
as a broad cryptography platform. Its first credible buyer is not a CISO who
wants to scan an entire enterprise. Its first credible buyer is a firmware
security lead, embedded OEM, MCU partner, or evaluation lab that needs a
repeatable way to review PQC firmware evidence.

The current repository is already unusually strong in local evidence
generation. The next product step is to make that evidence:

- stable enough for customer tooling;
- clear enough for partner review;
- physical-board-backed for at least one supported profile;
- signed or prepared for signing;
- packaged behind a simpler CLI;
- documented with support boundaries.

If those steps are completed, the project can become a credible proprietary
evaluation kit and then a supported embedded PQC assurance product. Without
those steps, it remains a sophisticated research prototype with impressive
local tooling but insufficient customer trust boundaries.

## Concrete Product Packaging Detail

The product should be packaged around evidence maturity rather than around algorithm
count. The repository already shows that algorithm support alone is not the strongest
differentiator. A buyer will care about whether the firmware module can be integrated,
tested, measured, audited, and handed to another reviewer with minimal ambiguity. The
commercial package should therefore name the evidence level being purchased and the
support boundary attached to that level.


### Package: Evaluation Workspace

Repository access, west consumer flow, QEMU release pack generation, schema-contract
validation, and offline replay for one internal review team.

- Buyer expectation: the package must produce a concrete artifact or review outcome, not
  just consulting notes.
- Repository dependency: the package should map directly to `release_check.py`,
  `verify_release_evidence_pack.py`, `validate_evidence_schemas.py`, the Passport
  scripts, and profile-specific evidence outputs.
- Sales boundary: do not imply certification, physical side-channel proof, or
  unsupported board readiness unless the specific evidence pack contains those
  artifacts.
- Upgrade path: the buyer can start with QEMU/local replay and then pay for board
  promotion, dashboard integration, custom policy overlays, or signed-pack support.

### Package: Partner Review Pack

A generated release evidence directory, human scorecard, CBOM, policy result, transcript
manifest, benchmark provenance, and replay instructions for a specific tag or commit.

- Buyer expectation: the package must produce a concrete artifact or review outcome, not
  just consulting notes.
- Repository dependency: the package should map directly to `release_check.py`,
  `verify_release_evidence_pack.py`, `validate_evidence_schemas.py`, the Passport
  scripts, and profile-specific evidence outputs.
- Sales boundary: do not imply certification, physical side-channel proof, or
  unsupported board readiness unless the specific evidence pack contains those
  artifacts.
- Upgrade path: the buyer can start with QEMU/local replay and then pay for board
  promotion, dashboard integration, custom policy overlays, or signed-pack support.

### Package: Board Promotion Pack

A hardware-focused add-on that captures UART transcripts, board metadata, benchmark
campaign rows, memory footprint, entropy notes, and board-specific failure recovery.

- Buyer expectation: the package must produce a concrete artifact or review outcome, not
  just consulting notes.
- Repository dependency: the package should map directly to `release_check.py`,
  `verify_release_evidence_pack.py`, `validate_evidence_schemas.py`, the Passport
  scripts, and profile-specific evidence outputs.
- Sales boundary: do not imply certification, physical side-channel proof, or
  unsupported board readiness unless the specific evidence pack contains those
  artifacts.
- Upgrade path: the buyer can start with QEMU/local replay and then pay for board
  promotion, dashboard integration, custom policy overlays, or signed-pack support.

### Package: Supplier Intake Verifier

A lightweight offline verifier and dashboard/data contract that a buyer can use to
inspect supplier-provided packs without building the firmware.

- Buyer expectation: the package must produce a concrete artifact or review outcome, not
  just consulting notes.
- Repository dependency: the package should map directly to `release_check.py`,
  `verify_release_evidence_pack.py`, `validate_evidence_schemas.py`, the Passport
  scripts, and profile-specific evidence outputs.
- Sales boundary: do not imply certification, physical side-channel proof, or
  unsupported board readiness unless the specific evidence pack contains those
  artifacts.
- Upgrade path: the buyer can start with QEMU/local replay and then pay for board
  promotion, dashboard integration, custom policy overlays, or signed-pack support.

### Package: Supported Integration Retainer

Support for Zephyr version updates, backend revision review, board enablement, policy
customization, and evidence-pack schema migration.

- Buyer expectation: the package must produce a concrete artifact or review outcome, not
  just consulting notes.
- Repository dependency: the package should map directly to `release_check.py`,
  `verify_release_evidence_pack.py`, `validate_evidence_schemas.py`, the Passport
  scripts, and profile-specific evidence outputs.
- Sales boundary: do not imply certification, physical side-channel proof, or
  unsupported board readiness unless the specific evidence pack contains those
  artifacts.
- Upgrade path: the buyer can start with QEMU/local replay and then pay for board
  promotion, dashboard integration, custom policy overlays, or signed-pack support.

## Customer Success Criteria By Profile

Profiles should become the customer-facing maturity model. A profile is useful only if
it names required evidence, allowed gaps, and the exact reason a pack is acceptable or
not acceptable for a use case.


### Profile `native_lab`

This repository profile should be explained to customers as an evidence boundary. Its
current description is: Local developer and partner-review profile that permits
validation-only harnesses and deterministic test material.. Product packaging should
preserve that machine-readable source of truth.

- Customer-ready outcome: the profile should have a one-page explanation, a required
  artifact list, a supported environment list, and a known limitations section.
- Engineering requirement: every profile result should be generated, schema-validated,
  summarized in migration readiness output, and visible in the partner scorecard.
- Support requirement: when a customer asks whether a deployment is acceptable, the
  answer should be framed as a profile decision backed by evidence, not as a vague
  yes/no statement.
- Commercial requirement: pricing and support should differ by profile because QEMU-only
  evidence, MCU build-only evidence, and physical hardware review have different effort
  and risk.

### Profile `qemu_release`

This repository profile should be explained to customers as an evidence boundary. Its
current description is: Replay-verifiable release profile backed by QEMU, native_sim,
transcripts, Passport artifacts, and local bundle metadata.. Product packaging should
preserve that machine-readable source of truth.

- Customer-ready outcome: the profile should have a one-page explanation, a required
  artifact list, a supported environment list, and a known limitations section.
- Engineering requirement: every profile result should be generated, schema-validated,
  summarized in migration readiness output, and visible in the partner scorecard.
- Support requirement: when a customer asks whether a deployment is acceptable, the
  answer should be framed as a profile decision backed by evidence, not as a vague
  yes/no statement.
- Commercial requirement: pricing and support should differ by profile because QEMU-only
  evidence, MCU build-only evidence, and physical hardware review have different effort
  and risk.

### Profile `mcu_minimal`

This repository profile should be explained to customers as an evidence boundary. Its
current description is: Build-only constrained MCU profile centered on the default ML-
KEM-768 and ML-DSA-65 protocol suite.. Product packaging should preserve that machine-
readable source of truth.

- Customer-ready outcome: the profile should have a one-page explanation, a required
  artifact list, a supported environment list, and a known limitations section.
- Engineering requirement: every profile result should be generated, schema-validated,
  summarized in migration readiness output, and visible in the partner scorecard.
- Support requirement: when a customer asks whether a deployment is acceptable, the
  answer should be framed as a profile decision backed by evidence, not as a vague
  yes/no statement.
- Commercial requirement: pricing and support should differ by profile because QEMU-only
  evidence, MCU build-only evidence, and physical hardware review have different effort
  and risk.

### Profile `gateway`

This repository profile should be explained to customers as an evidence boundary. Its
current description is: Higher-capacity embedded profile that permits all supported ML-
KEM and ML-DSA parameter sets with production RNG backends.. Product packaging should
preserve that machine-readable source of truth.

- Customer-ready outcome: the profile should have a one-page explanation, a required
  artifact list, a supported environment list, and a known limitations section.
- Engineering requirement: every profile result should be generated, schema-validated,
  summarized in migration readiness output, and visible in the partner scorecard.
- Support requirement: when a customer asks whether a deployment is acceptable, the
  answer should be framed as a profile decision backed by evidence, not as a vague
  yes/no statement.
- Commercial requirement: pricing and support should differ by profile because QEMU-only
  evidence, MCU build-only evidence, and physical hardware review have different effort
  and risk.

## Product Data Contract As Commercial Enabler

The evidence schema contract added to the repository is more than a developer
convenience. It is the product boundary that lets a dashboard, partner verifier,
customer policy tool, or procurement workflow consume the release pack without depending
on private implementation details. A serious product should treat the schema catalog as
an API.


### Product-MVP artifact `acvp_json_interop_result`

This artifact is required for the product-MVP profile and is expected at
`acvp_json_interop_result.json`. Its schema is
`artifacts/acvp_json_interop_result.schema.json`. Its product value is: Stabilizes
release evidence so tools can replay and inspect it..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `acvp_json_schema_result`

This artifact is required for the product-MVP profile and is expected at
`acvp_json_schema_result.json`. Its schema is
`artifacts/acvp_json_schema_result.schema.json`. Its product value is: Stabilizes
release evidence so tools can replay and inspect it..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `acvp_json_transcript_manifest`

This artifact is required for the product-MVP profile and is expected at
`acvp_json_transcript_manifest.json`. Its schema is
`artifacts/acvp_json_transcript_manifest.schema.json`. Its product value is: Binds
release claims to exact execution output..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `acvp_negative_scenario_floor_result`

This artifact is required for the product-MVP profile and is expected at
`acvp_negative_scenario_floor_result.json`. Its schema is
`artifacts/acvp_negative_scenario_floor_result.schema.json`. Its product value is:
Stabilizes release evidence so tools can replay and inspect it..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `assurance_ledger`

This artifact is required for the product-MVP profile and is expected at
`assurance_ledger.json`. Its schema is `artifacts/assurance_ledger.schema.json`. Its
product value is: Stabilizes release evidence so tools can replay and inspect it..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `assurance_report_html`

This artifact is required for the product-MVP profile and is expected at
`assurance_report.html`. Its schema is `artifacts/text_artifact.schema.json`. Its
product value is: Stabilizes release evidence so tools can replay and inspect it..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `backend_contract_result`

This artifact is required for the product-MVP profile and is expected at
`backend_contract_result.json`. Its schema is
`artifacts/backend_contract_result.schema.json`. Its product value is: Stabilizes
release evidence so tools can replay and inspect it..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `benchmark_campaign_result`

This artifact is required for the product-MVP profile and is expected at
`benchmark_campaign_result.json`. Its schema is
`artifacts/benchmark_campaign_result.schema.json`. Its product value is: Makes
performance evidence reproducible, comparable, and auditable..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `benchmark_campaign_verify_result`

This artifact is required for the product-MVP profile and is expected at
`benchmark_campaign_verify_result.json`. Its schema is
`artifacts/benchmark_campaign_verify_result.schema.json`. Its product value is: Makes
performance evidence reproducible, comparable, and auditable..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `benchmark_confidence_result`

This artifact is required for the product-MVP profile and is expected at
`benchmark_confidence_result.json`. Its schema is
`artifacts/benchmark_confidence_result.schema.json`. Its product value is: Makes
performance evidence reproducible, comparable, and auditable..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `benchmark_provenance`

This artifact is required for the product-MVP profile and is expected at
`benchmark_provenance.json`. Its schema is `artifacts/benchmark_provenance.schema.json`.
Its product value is: Makes performance evidence reproducible, comparable, and
auditable..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `benchmark_results_csv`

This artifact is required for the product-MVP profile and is expected at
`benchmark_results.csv`. Its schema is `artifacts/csv_artifact.schema.json`. Its product
value is: Makes performance evidence reproducible, comparable, and auditable..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `cost_of_assurance_evidence`

This artifact is required for the product-MVP profile and is expected at
`cost_of_assurance_evidence.json`. Its schema is
`artifacts/cost_of_assurance_evidence.schema.json`. Its product value is: Stabilizes
release evidence so tools can replay and inspect it..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `ct_instruction_policy_result`

This artifact is required for the product-MVP profile and is expected at
`ct_instruction_policy_result.json`. Its schema is
`artifacts/ct_instruction_policy_result.schema.json`. Its product value is: Converts raw
evidence into an explicit accept/reject decision..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `evidence_tamper_drill_result`

This artifact is required for the product-MVP profile and is expected at
`evidence_tamper_drill_result.json`. Its schema is
`artifacts/evidence_tamper_drill_result.schema.json`. Its product value is: Stabilizes
release evidence so tools can replay and inspect it..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `evidence_transcript_manifest`

This artifact is required for the product-MVP profile and is expected at
`transcripts/evidence_transcript_manifest.json`. Its schema is
`artifacts/evidence_transcript_manifest.schema.json`. Its product value is: Binds
release claims to exact execution output..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `mcu_protocol_footprint_csv`

This artifact is required for the product-MVP profile and is expected at
`mcu_protocol_footprint/cost_of_assurance_protocols_mcu.csv`. Its schema is
`artifacts/csv_artifact.schema.json`. Its product value is: Stabilizes release evidence
so tools can replay and inspect it..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `partner_review_scorecard`

This artifact is required for the product-MVP profile and is expected at
`partner_review_scorecard.json`. Its schema is
`artifacts/partner_review_scorecard.schema.json`. Its product value is: Provides a
concise partner-facing review summary..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `partner_review_scorecard_markdown`

This artifact is required for the product-MVP profile and is expected at
`partner_review_scorecard.md`. Its schema is `artifacts/text_artifact.schema.json`. Its
product value is: Provides a concise partner-facing review summary..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

### Product-MVP artifact `partner_review_scorecard_result`

This artifact is required for the product-MVP profile and is expected at
`partner_review_scorecard_result.json`. Its schema is
`artifacts/partner_review_scorecard_result.schema.json`. Its product value is: Provides
a concise partner-facing review summary..

- Customer value: this artifact gives a reviewer a stable object to inspect, archive,
  diff between releases, or ingest into a dashboard.
- Support value: when a pack fails validation, support can ask for this artifact and
  reproduce the failure locally without rebuilding the full Zephyr workspace.
- Packaging value: this artifact should be included in a release-pack manifest and
  described in product onboarding so customers know whether they are missing QEMU,
  policy, CBOM, benchmark, or transcript evidence.

## MVP Sales Qualification Checklist

- Does the customer use Zephyr or plan to evaluate Zephyr for embedded firmware? If no,
  this repository is not the first product to sell. The strongest current value is
  Zephyr module integration and Zephyr-targeted evidence.
- Does the customer need ML-KEM or ML-DSA in embedded firmware? If no, position the
  project as an assurance workflow preview, not as a direct production library.
- Can the customer accept local replay evidence before formal certification? If no, the
  sale must be framed as pre-certification engineering support, not a certified product.
- Does the customer have a physical target board available? If yes, board promotion is
  the highest-value paid engagement. If no, sell QEMU/local review as a lower-risk
  evaluation phase.
- Does the customer need supplier-review artifacts? If yes, emphasize CBOM, ledger,
  transcript hashes, policy replay, schema contract, and partner scorecard outputs.
- Does the customer need broad cryptography discovery? If yes, integrate with their
  inventory program instead of pretending this repository is an enterprise scanner.

## Concrete Roadmap To First Paid Pilot


### Week 0 readiness

Freeze a known-good commit, generate a sample product-MVP fixture, run schema
validation, run replay verification, and prepare a short partner guide.

- Repository output: at least one command transcript, one schema validation result, one
  replay verification result, and one human-readable summary should be produced for this
  phase.
- Customer output: the partner should know which claims passed, which claims are
  QEMU/local-only, which evidence is missing, and what it would cost or require to close
  the next profile level.

### Week 1 onboarding

Walk the partner through west setup, QEMU smoke, the offline verifier, and the
scorecard. Capture every command that required maintainer explanation.

- Repository output: at least one command transcript, one schema validation result, one
  replay verification result, and one human-readable summary should be produced for this
  phase.
- Customer output: the partner should know which claims passed, which claims are
  QEMU/local-only, which evidence is missing, and what it would cost or require to close
  the next profile level.

### Week 2 evidence review

Generate a partner-specific pack and review the ledger, CBOM, policy result, benchmark
provenance, transcript manifest, and schema-contract output.

- Repository output: at least one command transcript, one schema validation result, one
  replay verification result, and one human-readable summary should be produced for this
  phase.
- Customer output: the partner should know which claims passed, which claims are
  QEMU/local-only, which evidence is missing, and what it would cost or require to close
  the next profile level.

### Week 3 board scoping

Select one board, identify entropy and UART assumptions, decide whether the engagement
is build-only, UART-run, benchmark-run, or deeper hardware review.

- Repository output: at least one command transcript, one schema validation result, one
  replay verification result, and one human-readable summary should be produced for this
  phase.
- Customer output: the partner should know which claims passed, which claims are
  QEMU/local-only, which evidence is missing, and what it would cost or require to close
  the next profile level.

### Week 4 pilot close

Deliver a gap report, a verified pack, a compatibility entry, and a priced proposal for
board promotion or supported integration.

- Repository output: at least one command transcript, one schema validation result, one
  replay verification result, and one human-readable summary should be produced for this
  phase.
- Customer output: the partner should know which claims passed, which claims are
  QEMU/local-only, which evidence is missing, and what it would cost or require to close
  the next profile level.
