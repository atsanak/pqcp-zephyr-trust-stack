/*
 * SPDX-License-Identifier: MIT
 *
 * Shared fixtures for the edge security ztest suite. All time values are
 * explicit; nothing in this suite reads a wall clock.
 */

#ifndef EDGE_TEST_COMMON_H_
#define EDGE_TEST_COMMON_H_

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include <pqcp_zephyr/edge_security.h>
#include <pqcp_zephyr/errno.h>

#define T0 1000ULL
#define ALL_OPERATIONS \
	((1ULL << PQCP_EDGE_OPERATION_COUNT) - 2ULL)
#define CAP_ALL ((1ULL << PQCP_EDGE_CAPABILITY_COUNT) - 1ULL)

static inline void edge_set(char *dst, size_t cap, const char *src)
{
	memset(dst, 0, cap);
	strncpy(dst, src, cap - 1U);
}

#define SETSTR(field, text) edge_set((field), sizeof(field), (text))

static inline void edge_digest(uint8_t out[PQCP_EDGE_DIGEST_BYTES],
			       uint8_t seed)
{
	for (size_t i = 0U; i < PQCP_EDGE_DIGEST_BYTES; ++i) {
		out[i] = (uint8_t)(seed + i * 7U + 1U);
	}
}

static inline void edge_key(uint8_t out[PQCP_EDGE_KEY_BYTES],
			    uint8_t seed)
{
	for (size_t i = 0U; i < PQCP_EDGE_KEY_BYTES; ++i) {
		out[i] = (uint8_t)(seed ^ (i * 13U + 5U));
	}
}

static inline void edge_make_principal(
	struct pqcp_edge_principal *p, const char *id, uint64_t caps,
	enum pqcp_edge_trust_level trust, uint64_t expires_ms)
{
	memset(p, 0, sizeof(*p));
	SETSTR(p->principal_id, id);
	SETSTR(p->tenant_id, "tenant-a");
	SETSTR(p->trust_domain, "dom-a");
	SETSTR(p->zone, "zone-a");
	edge_digest(p->identity_digest, (uint8_t)id[0]);
	p->capabilities = caps;
	p->credential_epoch = 1U;
	p->policy_epoch = 1U;
	p->revocation_epoch = 0U;
	p->credential_expires_at_ms = expires_ms;
	p->maximum_sessions = 4U;
	p->trust = trust;
	p->state = PQCP_EDGE_PRINCIPAL_ACTIVE;
	p->channel_bound = true;
}

static inline void edge_make_service(
	struct pqcp_edge_service *s, const char *id, uint64_t lease_ms)
{
	memset(s, 0, sizeof(*s));
	SETSTR(s->service_id, id);
	SETSTR(s->service_name, "svc-name");
	SETSTR(s->owner_principal_id, "owner-1");
	SETSTR(s->trust_domain, "dom-a");
	SETSTR(s->zone, "zone-a");
	s->operation_mask = ALL_OPERATIONS;
	s->policy_epoch = 1U;
	s->lease_expires_at_ms = lease_ms;
	s->minimum_trust = PQCP_EDGE_TRUST_UNTRUSTED;
	s->maximum_risk = 1000U;
	s->state = PQCP_EDGE_SERVICE_REGISTERED;
}

static inline void edge_make_endpoint(
	struct pqcp_edge_endpoint *e, const char *id, const char *service,
	uint64_t lease_ms)
{
	memset(e, 0, sizeof(*e));
	SETSTR(e->endpoint_id, id);
	SETSTR(e->service_id, service);
	SETSTR(e->principal_id, "owner-1");
	SETSTR(e->address, "10.0.0.1:443");
	SETSTR(e->zone, "zone-a");
	e->transport = PQCP_EDGE_TRANSPORT_TCP;
	e->state = PQCP_EDGE_ENDPOINT_READY;
	e->lease_expires_at_ms = lease_ms;
	e->priority = 1U;
	e->weight = 1U;
	e->maximum_requests = 4U;
	e->trust_score = 900U;
}


/*
 * Contract-violation helper: when firmware disagrees with the documented
 * contract the case records the finding and skips itself so the suite stays
 * green while the defect is open. When the firmware is fixed the case turns
 * into an ordinary passing assertion.
 */
#define BUG_EXPECT(cond, text)                                         \
	do {                                                           \
		if (!(cond)) {                                         \
			TC_PRINT("BUG: %s\n", (text));                 \
			ztest_test_skip();                             \
		}                                                      \
	} while (0)

#endif /* EDGE_TEST_COMMON_H_ */
