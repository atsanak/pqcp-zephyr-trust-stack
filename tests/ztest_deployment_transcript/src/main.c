/*
 * SPDX-License-Identifier: MIT
 *
 * Deployment evidence transcript replay tests.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include <pqcp_zephyr/deployment_transcript.h>

#define CAMPAIGN_SUMMARY \
	"PQCP_DEPLOYMENT_CAMPAIGN_SUMMARY schema=1 id=m7_campaign projection=p90 observations=5 successful=5 failed=0 quality=0x00000000 projected=1 candidate=hybrid768_65_campaign evidence=0x00000fbf"
#define CAMPAIGN_SUMMARY_FAILED \
	"PQCP_DEPLOYMENT_CAMPAIGN_SUMMARY schema=1 id=m7_campaign projection=p90 observations=5 successful=4 failed=1 quality=0x00000024 projected=1 candidate=hybrid768_65_campaign evidence=0x00000fa7"
#define METRIC_LATENCY \
	"PQCP_DEPLOYMENT_CAMPAIGN_METRIC campaign=m7_campaign metric=latency count=5 missing=0 min=7200 median=7300 p90=7350 p99=7350 max=7425 mean=7311 mad=50 cv_bps=101 outliers=0 stable=1"
#define METRIC_CYCLES \
	"PQCP_DEPLOYMENT_CAMPAIGN_METRIC campaign=m7_campaign metric=cycles count=5 missing=0 min=2880000 median=2920000 p90=2940000 p99=2940000 max=2970000 mean=2924400 mad=20000 cv_bps=101 outliers=0 stable=1"
#define METRIC_RAM \
	"PQCP_DEPLOYMENT_CAMPAIGN_METRIC campaign=m7_campaign metric=ram count=5 missing=0 min=41000 median=41000 p90=41000 p99=41000 max=41000 mean=41000 mad=0 cv_bps=0 outliers=0 stable=1"
#define METRIC_STACK \
	"PQCP_DEPLOYMENT_CAMPAIGN_METRIC campaign=m7_campaign metric=stack count=5 missing=0 min=9000 median=9000 p90=9000 p99=9000 max=9000 mean=9000 mad=0 cv_bps=0 outliers=0 stable=1"
#define METRIC_HEAP \
	"PQCP_DEPLOYMENT_CAMPAIGN_METRIC campaign=m7_campaign metric=heap count=5 missing=0 min=3600 median=3600 p90=3600 p99=3600 max=3600 mean=3600 mad=0 cv_bps=0 outliers=0 stable=1"
#define METRIC_FLASH \
	"PQCP_DEPLOYMENT_CAMPAIGN_METRIC campaign=m7_campaign metric=flash count=5 missing=0 min=207000 median=207000 p90=207000 p99=207000 max=207000 mean=207000 mad=0 cv_bps=0 outliers=0 stable=1"
#define METRIC_ENERGY \
	"PQCP_DEPLOYMENT_CAMPAIGN_METRIC campaign=m7_campaign metric=energy count=5 missing=0 min=1720 median=1750 p90=1760 p99=1760 max=1780 mean=1751 mad=10 cv_bps=111 outliers=0 stable=1"
#define SCENARIO \
	"PQCP_DEPLOYMENT_SCENARIO schema=1 id=m7_device_onboarding operation=onboarding target=cortex_m7 security=3 preference=balanced evidence_level=product latency_budget_us=10000 ram_budget=65536 stack_budget=16384 heap_budget=8192 flash_budget=262144 energy_budget_uj=2500 native_required=1 hardware_required=1"
#define CANDIDATE_REJECTED \
	"PQCP_DEPLOYMENT_CANDIDATE scenario=m7_device_onboarding rank=0 id=mlkem512_qemu kind=mlkem target=qemu status=REJECTED score=0 confidence=35 blockers=0x00000006 gaps=0x00010828 security=1 mlkem=512 mldsa=0 latency_us=700 ram=7000 stack=1800 heap=0 flash=42000 energy_uj=0 evidence=0x00000fcf independent=0"
#define CANDIDATE_TOP \
	"PQCP_DEPLOYMENT_CANDIDATE scenario=m7_device_onboarding rank=1 id=hybrid768_65_campaign kind=hybrid_suite target=cortex_m7 status=ACCEPTED score=72 confidence=98 blockers=0x00000000 gaps=0x00000000 security=3 mlkem=768 mldsa=65 latency_us=7350 ram=41000 stack=9000 heap=3600 flash=207000 energy_uj=1760 evidence=0x00000fbf independent=1"
#define CANDIDATE_OTHER_TOP \
	"PQCP_DEPLOYMENT_CANDIDATE scenario=m7_device_onboarding rank=1 id=hybrid768_65_other kind=hybrid_suite target=cortex_m7 status=ACCEPTED score=70 confidence=95 blockers=0x00000000 gaps=0x00000000 security=3 mlkem=768 mldsa=65 latency_us=7400 ram=42000 stack=9100 heap=3600 flash=208000 energy_uj=1770 evidence=0x00000fbf independent=1"
#define ROBUST_REJECTED \
	"PQCP_DEPLOYMENT_ROBUSTNESS_CANDIDATE schema=1 index=0 id=mlkem512_qemu status=REJECTED score=0 configured=0x0000003f measured=0x00000017 missing=0x00000028 binding=flash min_headroom_permille=839 avg_headroom_permille=888 preference_wins=0x00000000 stress_pass=0x00000000 max_reduction_percent=83 dominates=0 dominated_by=0 pareto=0 complete=0"
#define ROBUST_TOP \
	"PQCP_DEPLOYMENT_ROBUSTNESS_CANDIDATE schema=1 index=1 id=hybrid768_65_campaign status=ROBUST score=60 configured=0x0000003f measured=0x0000003f missing=0x00000000 binding=flash min_headroom_permille=210 avg_headroom_permille=359 preference_wins=0x0000000f stress_pass=0x00000007 max_reduction_percent=21 dominates=1 dominated_by=0 pareto=1 complete=1"
#define ROBUST_OTHER_TOP \
	"PQCP_DEPLOYMENT_ROBUSTNESS_CANDIDATE schema=1 index=1 id=hybrid768_65_other status=ROBUST score=55 configured=0x0000003f measured=0x0000003f missing=0x00000000 binding=flash min_headroom_permille=205 avg_headroom_permille=350 preference_wins=0x0000000f stress_pass=0x00000007 max_reduction_percent=20 dominates=1 dominated_by=0 pareto=1 complete=1"
#define DECISION \
	"PQCP_DEPLOYMENT_DECISION schema=1 id=m7_device_onboarding status=PASS candidates=2 feasible=1 accepted=1 conditional=0 rejected=1 top=hybrid768_65_campaign top_score=72 top_confidence=98"
#define DECISION_COUNT_BAD \
	"PQCP_DEPLOYMENT_DECISION schema=1 id=m7_device_onboarding status=PASS candidates=3 feasible=1 accepted=1 conditional=0 rejected=1 top=hybrid768_65_campaign top_score=72 top_confidence=98"
#define DECISION_TOP_BAD \
	"PQCP_DEPLOYMENT_DECISION schema=1 id=m7_device_onboarding status=PASS candidates=2 feasible=1 accepted=1 conditional=0 rejected=1 top=missing_top top_score=72 top_confidence=98"
#define DECISION_OTHER_TOP \
	"PQCP_DEPLOYMENT_DECISION schema=1 id=m7_device_onboarding status=PASS candidates=2 feasible=1 accepted=1 conditional=0 rejected=1 top=hybrid768_65_other top_score=70 top_confidence=95"
#define DECISION_FAIL \
	"PQCP_DEPLOYMENT_DECISION schema=1 id=m7_device_onboarding status=NO_RECOMMENDATION candidates=2 feasible=0 accepted=0 conditional=0 rejected=2 top=none top_score=0 top_confidence=0"
#define ROBUSTNESS \
	"PQCP_DEPLOYMENT_ROBUSTNESS schema=1 id=m7_device_onboarding status=ROBUST candidates=2 feasible=1 frontier=1 top=hybrid768_65_campaign top_score=60 top_preference_wins=4 stable=1 robust=1"
#define ROBUSTNESS_OTHER_TOP \
	"PQCP_DEPLOYMENT_ROBUSTNESS schema=1 id=m7_device_onboarding status=ROBUST candidates=2 feasible=1 frontier=1 top=hybrid768_65_other top_score=55 top_preference_wins=4 stable=1 robust=1"
#define ROBUSTNESS_COUNT_BAD \
	"PQCP_DEPLOYMENT_ROBUSTNESS schema=1 id=m7_device_onboarding status=ROBUST candidates=2 feasible=1 frontier=2 top=hybrid768_65_campaign top_score=60 top_preference_wins=4 stable=1 robust=1"
#define GAP \
	"PQCP_DEPLOYMENT_GAP priority=1 candidate=mlkem512_qemu gap=hardware maturity=product acceptance_max=0 expected=hardware_benchmark_transcript claim=claim.deployment_physical_target"

static int replay_lines(
	const char *const *lines,
	size_t line_count,
	struct pqcp_deployment_transcript_result *result)
{
	struct pqcp_deployment_transcript_state state;
	int ret = 0;

	zassert_equal(pqcp_deployment_transcript_init(&state), 0);
	for (size_t i = 0U; i < line_count; ++i) {
		ret = pqcp_deployment_transcript_ingest_line(&state, lines[i]);
		if (ret != 0) {
			break;
		}
	}

	return pqcp_deployment_transcript_finish(&state, result);
}

static void assert_replay_error(
	const char *const *lines,
	size_t line_count,
	enum pqcp_deployment_transcript_error expected_error)
{
	struct pqcp_deployment_transcript_result result;

	zassert_equal(replay_lines(lines, line_count, &result), -EBADMSG);
	zassert_false(result.passed);
	zassert_equal(result.first_error, expected_error,
		      "unexpected replay error: %s",
		      pqcp_deployment_transcript_error_str(result.first_error));
	zassert_not_equal(result.first_error_line, 0U);
}

ZTEST(pqcp_deployment_transcript, test_tokens_are_stable)
{
	zassert_true(strcmp(pqcp_deployment_transcript_error_str(
				    PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_NONE),
			    "none") == 0);
	zassert_true(strcmp(pqcp_deployment_transcript_error_str(
				    PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_TOP_MISMATCH),
			    "top_mismatch") == 0);
	zassert_true(strcmp(pqcp_deployment_transcript_error_str(
				    (enum pqcp_deployment_transcript_error)99),
			    "unknown") == 0);
}

ZTEST(pqcp_deployment_transcript, test_valid_deployment_transcript_passes)
{
	static const char *const lines[] = {
		"*** Booting Zephyr OS build v4.4.0 ***",
		CAMPAIGN_SUMMARY,
		METRIC_LATENCY,
		METRIC_CYCLES,
		METRIC_RAM,
		METRIC_STACK,
		METRIC_HEAP,
		METRIC_FLASH,
		METRIC_ENERGY,
		SCENARIO,
		CANDIDATE_REJECTED,
		ROBUST_REJECTED,
		CANDIDATE_TOP,
		ROBUST_TOP,
		DECISION,
		ROBUSTNESS,
		GAP,
		"PROJECT EXECUTION SUCCESSFUL",
	};
	struct pqcp_deployment_transcript_result result;

	zassert_equal(replay_lines(lines, ARRAY_SIZE(lines), &result), 0);
	zassert_true(result.passed);
	zassert_equal(result.candidate_count, 2U);
	zassert_equal(result.robustness_candidate_count, 2U);
	zassert_equal(result.campaign_metric_count, 7U);
	zassert_equal(result.gap_count, 1U);
	zassert_true((result.marker_mask &
		      PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_CAMPAIGN) != 0U);
	zassert_true((result.marker_mask &
		      PQCP_DEPLOYMENT_TRANSCRIPT_MARKER_ROBUSTNESS) != 0U);
}

ZTEST(pqcp_deployment_transcript, test_count_mismatch_fails)
{
	static const char *const lines[] = {
		SCENARIO,
		CANDIDATE_REJECTED,
		CANDIDATE_TOP,
		ROBUST_REJECTED,
		ROBUST_TOP,
		DECISION_COUNT_BAD,
		ROBUSTNESS,
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_COUNT_MISMATCH);
}

ZTEST(pqcp_deployment_transcript, test_top_mismatch_fails)
{
	static const char *const lines[] = {
		SCENARIO,
		CANDIDATE_REJECTED,
		CANDIDATE_TOP,
		ROBUST_REJECTED,
		ROBUST_TOP,
		DECISION_TOP_BAD,
		ROBUSTNESS,
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_TOP_MISMATCH);
}

ZTEST(pqcp_deployment_transcript, test_campaign_missing_metric_fails)
{
	static const char *const lines[] = {
		CAMPAIGN_SUMMARY,
		METRIC_LATENCY,
		METRIC_CYCLES,
		METRIC_RAM,
		METRIC_STACK,
		METRIC_HEAP,
		METRIC_FLASH,
		SCENARIO,
		CANDIDATE_REJECTED,
		ROBUST_REJECTED,
		CANDIDATE_TOP,
		ROBUST_TOP,
		DECISION,
		ROBUSTNESS,
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_CAMPAIGN_MISMATCH);
}

ZTEST(pqcp_deployment_transcript, test_campaign_candidate_missing_fails)
{
	static const char *const lines[] = {
		CAMPAIGN_SUMMARY,
		METRIC_LATENCY,
		METRIC_CYCLES,
		METRIC_RAM,
		METRIC_STACK,
		METRIC_HEAP,
		METRIC_FLASH,
		METRIC_ENERGY,
		SCENARIO,
		CANDIDATE_REJECTED,
		ROBUST_REJECTED,
		CANDIDATE_OTHER_TOP,
		ROBUST_OTHER_TOP,
		DECISION_OTHER_TOP,
		ROBUSTNESS_OTHER_TOP,
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_CAMPAIGN_MISMATCH);
}

ZTEST(pqcp_deployment_transcript, test_failed_summary_status_fails)
{
	static const char *const decision_lines[] = {
		SCENARIO,
		CANDIDATE_REJECTED,
		ROBUST_REJECTED,
		DECISION_FAIL,
	};
	static const char *const campaign_lines[] = {
		CAMPAIGN_SUMMARY_FAILED,
	};

	assert_replay_error(decision_lines, ARRAY_SIZE(decision_lines),
			    PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_STATUS_FAIL);
	assert_replay_error(campaign_lines, ARRAY_SIZE(campaign_lines),
			    PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_STATUS_FAIL);
}

ZTEST(pqcp_deployment_transcript, test_bad_order_and_duplicate_fails)
{
	static const char *const bad_order[] = {
		CANDIDATE_TOP,
		SCENARIO,
	};
	static const char *const duplicate_summary[] = {
		SCENARIO,
		SCENARIO,
	};

	assert_replay_error(bad_order, ARRAY_SIZE(bad_order),
			    PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_BAD_SEQUENCE);
	assert_replay_error(duplicate_summary, ARRAY_SIZE(duplicate_summary),
			    PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_DUPLICATE_SUMMARY);
}

ZTEST(pqcp_deployment_transcript, test_robustness_frontier_mismatch_fails)
{
	static const char *const lines[] = {
		SCENARIO,
		CANDIDATE_REJECTED,
		CANDIDATE_TOP,
		ROBUST_REJECTED,
		ROBUST_TOP,
		DECISION,
		ROBUSTNESS_COUNT_BAD,
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_ROBUSTNESS_MISMATCH);
}

ZTEST(pqcp_deployment_transcript, test_finish_without_required_fails)
{
	static const char *const lines[] = {
		"noise only",
	};

	assert_replay_error(lines, ARRAY_SIZE(lines),
			    PQCP_DEPLOYMENT_TRANSCRIPT_ERROR_MISSING_REQUIRED);
}

ZTEST_SUITE(pqcp_deployment_transcript, NULL, NULL, NULL, NULL, NULL);
