/*
 * SPDX-License-Identifier: MIT
 *
 * Confidential object vault: store, ACL, versions, leases, journal,
 * replication, snapshots and audit export.
 */

#include "edge_security_internal.h"
#include "test_common.h"

#define PERM_RW (PQCP_EDGE_VAULT_PERMISSION_READ | \
		 PQCP_EDGE_VAULT_PERMISSION_WRITE)
#define PERM_RWD (PERM_RW | PQCP_EDGE_VAULT_PERMISSION_DELETE)

/* ------------------------------------------------------------------ */
/* Vault store                                                         */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_vault_object vstore[2];
static struct pqcp_edge_vault_store vs;

static void vault_setup(void)
{
	zassert_equal(pqcp_edge_vault_store_init(
		&vs, vstore, ARRAY_SIZE(vstore)), 0);
}

static void make_obj(struct pqcp_edge_vault_object *o, const char *id,
		     const char *owner, const char *value)
{
	memset(o, 0, sizeof(*o));
	SETSTR(o->object_id, id);
	SETSTR(o->namespace_id, "ns");
	SETSTR(o->owner_id, owner);
	SETSTR(o->classification, "secret");
	o->version = 1U;
	o->policy_epoch = 1U;
	o->permissions = PERM_RWD;
	o->value_length = strlen(value);
	memcpy(o->value, value, o->value_length);
	o->encrypted = true;
}

static void create_obj(const char *id, const char *owner, const char *value)
{
	struct pqcp_edge_vault_object o;

	make_obj(&o, id, owner, value);
	zassert_equal(pqcp_edge_vault_create(&vs, &o, T0), 0);
}

ZTEST(edge_security, test_vault_store_rejects_invalid_arguments)
{
	static struct pqcp_edge_vault_store raw;
	struct pqcp_edge_vault_object o;
	struct pqcp_edge_vault_object *found = (void *)0x1;
	uint8_t out[16];
	size_t length = 99U;
	uint32_t changed = 0U;
	uint8_t big[PQCP_EDGE_VAULT_VALUE_MAX_BYTES + 1U] = { 1 };

	zassert_equal(pqcp_edge_vault_store_init(NULL, vstore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_vault_store_init(&vs, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_vault_store_init(&vs, vstore, 0U), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_obj(&o, "o1", "alice", "v");
	zassert_equal(pqcp_edge_vault_create(&raw, &o, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_read(&raw, "o1", out, sizeof(out),
		&length, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_write(&raw, "o1", out, 1U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_seal(&raw, "o1", T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_delete(&raw, "o1", 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_find(&raw, "o1", &found), -EINVAL);
	zassert_equal(pqcp_edge_vault_tick(&raw, T0, &changed), -EINVAL);
	zassert_equal(pqcp_edge_vault_store_audit(&raw), -EINVAL);

	vault_setup();
	zassert_equal(pqcp_edge_vault_create(&vs, NULL, T0), -EINVAL);
#define BAD_OBJ(mut)                                                  \
	do {                                                          \
		make_obj(&o, "o1", "alice", "v");                     \
		mut;                                                  \
		zassert_equal(pqcp_edge_vault_create(&vs, &o, T0),    \
			      -EINVAL, #mut);                         \
	} while (0)
	BAD_OBJ(o.object_id[0] = '\0');
	BAD_OBJ(o.namespace_id[0] = '\0');
	BAD_OBJ(o.owner_id[0] = '\0');
	BAD_OBJ(o.classification[0] = '\0');
	BAD_OBJ(o.version = 0U);
	BAD_OBJ(o.policy_epoch = 0U);
	BAD_OBJ(o.permissions = 0U);
	BAD_OBJ(o.value_length = 0U);
	BAD_OBJ(o.value_length = sizeof(o.value) + 1U);
	BAD_OBJ(o.state = (enum pqcp_edge_vault_object_state)9);
	BAD_OBJ(o.created_at_ms = T0 + 1U);
	BAD_OBJ(o.expires_at_ms = T0);
#undef BAD_OBJ
	zassert_false(vstore[0].occupied);
	zassert_equal(vs.create_count, 0U);

	zassert_equal(pqcp_edge_vault_read(&vs, NULL, out, sizeof(out),
		&length, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_read(&vs, "o1", NULL, 16U, &length,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_read(&vs, "o1", out, sizeof(out),
		NULL, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_read(&vs, "o1", out, sizeof(out),
		&length, T0), -ENOENT);
	zassert_equal(length, 99U);
	zassert_equal(pqcp_edge_vault_write(&vs, NULL, out, 1U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_write(&vs, "o1", NULL, 1U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_write(&vs, "o1", out, 0U, 1U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_write(&vs, "o1", big, sizeof(big), 1U,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_write(&vs, "o1", out, 1U, 0U, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_write(&vs, "o1", out, 1U, 1U, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_vault_seal(&vs, NULL, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_seal(&vs, "o1", T0), -ENOENT);
	zassert_equal(pqcp_edge_vault_delete(&vs, NULL, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_delete(&vs, "o1", 0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_delete(&vs, "o1", 1U, T0), -ENOENT);
	zassert_equal(pqcp_edge_vault_find(&vs, "o1", NULL), -EINVAL);
	zassert_equal(pqcp_edge_vault_find(&vs, "o1", &found), -ENOENT);
	zassert_is_null(found);
	zassert_equal(pqcp_edge_vault_tick(&vs, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_vault_store_audit(&vs), 0);
}

ZTEST(edge_security, test_vault_create_read_write_versioning)
{
	struct pqcp_edge_vault_object *o = NULL;
	uint8_t out[32];
	size_t length = 0U;
	uint8_t old_digest[PQCP_EDGE_DIGEST_BYTES];

	vault_setup();
	create_obj("o1", "alice", "first");
	zassert_equal(pqcp_edge_vault_find(&vs, "o1", &o), 0);
	zassert_equal(o->version, 1U);
	zassert_equal(o->state, PQCP_EDGE_VAULT_ACTIVE);
	zassert_equal(o->created_at_ms, T0);
	zassert_false(pqcp_edge_internal_all_zero(o->object_digest,
		sizeof(o->object_digest)));
	zassert_equal(vs.create_count, 1U);

	zassert_equal(pqcp_edge_vault_read(&vs, "o1", out, sizeof(out),
		&length, T0 + 1U), 0);
	zassert_equal(length, 5U);
	zassert_mem_equal(out, "first", 5U);
	/* Buffer too small: error and zero length, nothing copied. */
	memset(out, 0xaa, sizeof(out));
	zassert_equal(pqcp_edge_vault_read(&vs, "o1", out, 4U, &length,
		T0 + 1U), -ENOBUFS);
	zassert_equal(length, 0U);
	zassert_equal(out[0], 0xaaU);

	/* Duplicate creation is refused and counted. */
	{
		struct pqcp_edge_vault_object dup;

		make_obj(&dup, "o1", "mallory", "evil");
		zassert_equal(pqcp_edge_vault_create(&vs, &dup, T0 + 2U),
			      -EEXIST);
		zassert_equal(vs.rejection_count, 1U);
		zassert_str_equal(o->owner_id, "alice");
	}

	/* Optimistic concurrency: stale version never overwrites. */
	memcpy(old_digest, o->object_digest, sizeof(old_digest));
	zassert_equal(pqcp_edge_vault_write(&vs, "o1",
		(const uint8_t *)"second", 6U, 2U, T0 + 3U), -ESTALE);
	zassert_equal(o->version, 1U);
	zassert_mem_equal(o->value, "first", 5U);
	zassert_equal(vs.rejection_count, 2U);
	zassert_equal(pqcp_edge_vault_write(&vs, "o1",
		(const uint8_t *)"second", 6U, 1U, T0 + 3U), 0);
	zassert_equal(o->version, 2U);
	zassert_equal(o->updated_at_ms, T0 + 3U);
	zassert_equal(o->value_length, 6U);
	zassert_true(memcmp(old_digest, o->object_digest,
			    sizeof(old_digest)) != 0);
	zassert_equal(vs.update_count, 1U);
	/* Replaying the old write fails now. */
	zassert_equal(pqcp_edge_vault_write(&vs, "o1",
		(const uint8_t *)"second", 6U, 1U, T0 + 4U), -ESTALE);
	zassert_equal(pqcp_edge_vault_store_audit(&vs), 0);
}

ZTEST(edge_security, test_vault_sealed_objects_are_read_only)
{
	struct pqcp_edge_vault_object *o = NULL;
	uint8_t out[16];
	size_t length = 0U;

	vault_setup();
	create_obj("o1", "alice", "data");
	zassert_equal(pqcp_edge_vault_seal(&vs, "o1", T0 + 1U), 0);
	zassert_equal(pqcp_edge_vault_find(&vs, "o1", &o), 0);
	zassert_equal(o->state, PQCP_EDGE_VAULT_SEALED);
	zassert_equal(pqcp_edge_vault_seal(&vs, "o1", T0 + 2U), -EALREADY);
	zassert_equal(pqcp_edge_vault_write(&vs, "o1",
		(const uint8_t *)"new", 3U, 1U, T0 + 3U), -EROFS);
	zassert_mem_equal(o->value, "data", 4U);
	zassert_equal(o->version, 1U);
	/* Reads remain possible and verified. */
	zassert_equal(pqcp_edge_vault_read(&vs, "o1", out, sizeof(out),
		&length, T0 + 4U), 0);
	zassert_equal(length, 4U);
	zassert_equal(pqcp_edge_vault_store_audit(&vs), 0);
}

ZTEST(edge_security, test_vault_delete_tombstones_and_wipes_value)
{
	struct pqcp_edge_vault_object *o = NULL;
	uint8_t out[16];
	size_t length = 7U;

	vault_setup();
	create_obj("o1", "alice", "topsecret");
	zassert_equal(pqcp_edge_vault_delete(&vs, "o1", 9U, T0 + 1U),
		      -ESTALE);
	zassert_equal(pqcp_edge_vault_find(&vs, "o1", &o), 0);
	zassert_equal(o->state, PQCP_EDGE_VAULT_ACTIVE);
	zassert_equal(pqcp_edge_vault_delete(&vs, "o1", 1U, T0 + 2U), 0);
	zassert_equal(o->state, PQCP_EDGE_VAULT_TOMBSTONED);
	zassert_equal(o->version, 2U);
	zassert_equal(o->value_length, 1U);
	zassert_equal(o->value[0], 0U);
	zassert_equal(pqcp_edge_internal_all_zero(o->value, 16U), true);
	zassert_equal(vs.delete_count, 1U);

	zassert_equal(pqcp_edge_vault_read(&vs, "o1", out, sizeof(out),
		&length, T0 + 3U), -EACCES);
	zassert_equal(length, 0U);
	zassert_equal(pqcp_edge_vault_write(&vs, "o1",
		(const uint8_t *)"zombie", 6U, 2U, T0 + 3U), -EACCES);
	zassert_equal(pqcp_edge_vault_seal(&vs, "o1", T0 + 3U), -EACCES);
	zassert_equal(pqcp_edge_vault_delete(&vs, "o1", 1U, T0 + 3U),
		      -ESTALE);
	zassert_equal(pqcp_edge_vault_delete(&vs, "o1", 2U, T0 + 3U),
		      -EALREADY);
	zassert_equal(vs.delete_count, 1U);
	zassert_equal(pqcp_edge_vault_store_audit(&vs), 0);
}

ZTEST(edge_security, test_vault_expiry_read_refusal_and_tick)
{
	struct pqcp_edge_vault_object o;
	struct pqcp_edge_vault_object *found = NULL;
	uint8_t out[16];
	size_t length = 0U;
	uint32_t changed = 0U;

	vault_setup();
	make_obj(&o, "o1", "alice", "short-lived");
	o.expires_at_ms = T0 + 100U;
	zassert_equal(pqcp_edge_vault_create(&vs, &o, T0), 0);
	create_obj("o2", "alice", "forever");

	zassert_equal(pqcp_edge_vault_read(&vs, "o1", out, sizeof(out),
		&length, T0 + 99U), 0);
	zassert_equal(pqcp_edge_vault_read(&vs, "o1", out, sizeof(out),
		&length, T0 + 100U), -EKEYEXPIRED);
	zassert_equal(length, 0U);

	zassert_equal(pqcp_edge_vault_tick(&vs, T0 + 100U, &changed), 0);
	zassert_equal(changed, 1U);
	zassert_equal(pqcp_edge_vault_find(&vs, "o1", &found), 0);
	zassert_equal(found->state, PQCP_EDGE_VAULT_TOMBSTONED);
	zassert_equal(found->value_length, 1U);
	zassert_equal(found->value[0], 0U);
	/* Only expired objects were touched; second tick is a no-op. */
	zassert_equal(pqcp_edge_vault_find(&vs, "o2", &found), 0);
	zassert_equal(found->state, PQCP_EDGE_VAULT_ACTIVE);
	zassert_equal(pqcp_edge_vault_tick(&vs, T0 + 200U, &changed), 0);
	zassert_equal(changed, 0U);
	zassert_equal(pqcp_edge_vault_store_audit(&vs), 0);
}

ZTEST(edge_security, test_vault_capacity_and_integrity_audit)
{
	struct pqcp_edge_vault_object o;
	struct pqcp_edge_vault_object *found = NULL;
	struct pqcp_edge_vault_object snap;
	uint8_t out[16];
	size_t length = 5U;

	vault_setup();
	create_obj("o1", "alice", "aaa");
	create_obj("o2", "alice", "bbb");
	snap = vstore[0];
	make_obj(&o, "o3", "alice", "ccc");
	zassert_equal(pqcp_edge_vault_create(&vs, &o, T0 + 1U), -ENOSPC);
	zassert_mem_equal(&vstore[0], &snap, sizeof(snap));
	zassert_equal(vs.rejection_count, 1U);
	zassert_equal(vs.create_count, 2U);

	/* Value tampering is caught by reads and by the audit. */
	zassert_equal(pqcp_edge_vault_find(&vs, "o2", &found), 0);
	found->value[0] ^= 1U;
	zassert_equal(pqcp_edge_vault_read(&vs, "o2", out, sizeof(out),
		&length, T0 + 2U), -EBADMSG);
	zassert_equal(length, 0U);
	zassert_equal(pqcp_edge_vault_store_audit(&vs), -EBADMSG);
	found->value[0] ^= 1U;
	zassert_equal(pqcp_edge_vault_store_audit(&vs), 0);
	/* Metadata tampering (owner reassignment) is caught as well. */
	SETSTR(found->owner_id, "mallory");
	zassert_equal(pqcp_edge_vault_store_audit(&vs), -EBADMSG);
	SETSTR(found->owner_id, "alice");
	vstore[1] = vstore[0];
	zassert_equal(pqcp_edge_vault_store_audit(&vs), -EEXIST);
}

ZTEST(edge_security, test_vault_sealed_object_cannot_be_deleted)
{
	struct pqcp_edge_vault_object *o = NULL;
	int ret;

	vault_setup();
	create_obj("o1", "alice", "evidence");
	zassert_equal(pqcp_edge_vault_seal(&vs, "o1", T0 + 1U), 0);
	ret = pqcp_edge_vault_delete(&vs, "o1", 1U, T0 + 2U);
	zassert_equal(ret, -EROFS);
	zassert_equal(pqcp_edge_vault_find(&vs, "o1", &o), 0);
	zassert_equal(o->state, PQCP_EDGE_VAULT_SEALED);
	zassert_equal(o->version, 1U);
	zassert_equal(vs.delete_count, 0U);
	zassert_equal(pqcp_edge_vault_store_audit(&vs), 0);
}

/* ------------------------------------------------------------------ */
/* Vault ACL                                                           */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_vault_acl_entry astore[2];
static struct pqcp_edge_vault_acl acl;

static void acl_setup(void)
{
	zassert_equal(pqcp_edge_vault_acl_init(
		&acl, astore, ARRAY_SIZE(astore)), 0);
}

static void make_acl(struct pqcp_edge_vault_acl_entry *e, const char *obj,
		     const char *who, uint32_t perms)
{
	memset(e, 0, sizeof(*e));
	SETSTR(e->object_id, obj);
	SETSTR(e->principal_id, who);
	e->permissions = perms;
	e->maximum_risk = 500U;
	e->minimum_trust = PQCP_EDGE_TRUST_AUTHENTICATED;
}

ZTEST(edge_security, test_vault_acl_rejects_invalid_arguments)
{
	static struct pqcp_edge_vault_acl raw;
	struct pqcp_edge_vault_acl_entry e;
	struct pqcp_edge_vault_object o;
	struct pqcp_edge_principal p;
	uint32_t expired = 0U;

	zassert_equal(pqcp_edge_vault_acl_init(NULL, astore, 2U), -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_init(&acl, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_init(&acl, astore, 0U), -EINVAL);

	memset(&raw, 0, sizeof(raw));
	make_acl(&e, "o1", "bob", PQCP_EDGE_VAULT_PERMISSION_READ);
	make_obj(&o, "o1", "alice", "v");
	o.occupied = true;
	edge_make_principal(&p, "bob", 1U, PQCP_EDGE_TRUST_ATTESTED, 900000U);
	zassert_equal(pqcp_edge_vault_acl_put(&raw, &e), -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_remove(&raw, "o1", "bob"), -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_authorize(&raw, &o, &p,
		PQCP_EDGE_VAULT_PERMISSION_READ, true, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_expire(&raw, T0, &expired),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_audit(&raw), -EINVAL);

	acl_setup();
	zassert_equal(pqcp_edge_vault_acl_put(&acl, NULL), -EINVAL);
	make_acl(&e, "o1", "bob", 0U);
	zassert_equal(pqcp_edge_vault_acl_put(&acl, &e), -EINVAL);
	make_acl(&e, "o1", "bob", 1U << 12);
	zassert_equal(pqcp_edge_vault_acl_put(&acl, &e), -EINVAL);
	make_acl(&e, "o1", "bob", 1U);
	e.object_id[0] = '\0';
	zassert_equal(pqcp_edge_vault_acl_put(&acl, &e), -EINVAL);
	make_acl(&e, "o1", "bob", 1U);
	e.not_before_ms = 500U;
	e.expires_at_ms = 100U;
	zassert_equal(pqcp_edge_vault_acl_put(&acl, &e), -EINVAL);
	make_acl(&e, "o1", "bob", 1U);
	e.minimum_trust = (enum pqcp_edge_trust_level)42;
	zassert_equal(pqcp_edge_vault_acl_put(&acl, &e), -EINVAL);
	zassert_false(astore[0].occupied);

	zassert_equal(pqcp_edge_vault_acl_remove(&acl, NULL, "bob"), -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_remove(&acl, "o1", NULL), -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_remove(&acl, "o1", "bob"),
		      -ENOENT);
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, NULL, &p, 1U, true,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, NULL, 1U, true,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, 0U, true,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, 1U << 20,
		true, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_expire(&acl, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_vault_acl_audit(&acl), 0);
}

ZTEST(edge_security, test_vault_acl_denies_by_default_and_enforces_conditions)
{
	struct pqcp_edge_vault_acl_entry e;
	struct pqcp_edge_vault_object o;
	struct pqcp_edge_principal p;
	const uint32_t read = PQCP_EDGE_VAULT_PERMISSION_READ;

	acl_setup();
	make_obj(&o, "o1", "alice", "v");
	o.occupied = true;
	o.state = PQCP_EDGE_VAULT_ACTIVE;
	edge_make_principal(&p, "bob", 0U, PQCP_EDGE_TRUST_ATTESTED, 900000U);

	/* No entry: deny. */
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read,
		true, T0), -EACCES);
	zassert_equal(acl.deny_count, 1U);

	make_acl(&e, "o1", "bob", read);
	e.not_before_ms = T0 + 100U;
	e.expires_at_ms = T0 + 1000U;
	e.maximum_uses = 2U;
	e.require_attestation = true;
	e.minimum_trust = PQCP_EDGE_TRUST_ATTESTED;
	zassert_equal(pqcp_edge_vault_acl_put(&acl, &e), 0);

	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, true,
		T0 + 99U), -EAGAIN);
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, true,
		T0 + 1000U), -EKEYEXPIRED);
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p,
		PQCP_EDGE_VAULT_PERMISSION_WRITE, true, T0 + 100U), -EACCES);
	p.risk_score = 501U;
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, true,
		T0 + 100U), -EACCES);
	p.risk_score = 0U;
	p.trust = PQCP_EDGE_TRUST_AUTHENTICATED;
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, true,
		T0 + 100U), -EAGAIN);
	p.trust = PQCP_EDGE_TRUST_ATTESTED;
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, false,
		T0 + 100U), -EAGAIN);
	/* None of the denials consumed a use. */
	zassert_equal(astore[0].use_count, 0U);

	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, true,
		T0 + 100U), 0);
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, true,
		T0 + 101U), 0);
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, true,
		T0 + 102U), -EDQUOT);
	zassert_equal(astore[0].use_count, 2U);
	zassert_equal(acl.allow_count, 2U);

	/* Principal and object state gates are independent of the entry. */
	p.state = PQCP_EDGE_PRINCIPAL_DEGRADED;
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, true,
		T0 + 100U), -EACCES);
	p.state = PQCP_EDGE_PRINCIPAL_ACTIVE;
	p.credential_expires_at_ms = T0 + 100U;
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, true,
		T0 + 100U), -EACCES);
	p.credential_expires_at_ms = 900000U;
	o.state = PQCP_EDGE_VAULT_TOMBSTONED;
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, true,
		T0 + 100U), -EACCES);
	o.state = PQCP_EDGE_VAULT_QUARANTINED;
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, true,
		T0 + 100U), -EACCES);
	o.state = PQCP_EDGE_VAULT_ACTIVE;
	o.occupied = false;
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &p, read, true,
		T0 + 100U), -EACCES);
}

ZTEST(edge_security, test_vault_acl_owner_fast_path_and_maintenance)
{
	struct pqcp_edge_vault_acl_entry e;
	struct pqcp_edge_vault_acl_entry snap[2];
	struct pqcp_edge_vault_object o;
	struct pqcp_edge_principal owner;
	uint32_t expired = 0U;

	acl_setup();
	make_obj(&o, "o1", "alice", "v");
	o.occupied = true;
	o.state = PQCP_EDGE_VAULT_ACTIVE;
	o.permissions = PQCP_EDGE_VAULT_PERMISSION_READ;
	edge_make_principal(&owner, "alice", 0U, PQCP_EDGE_TRUST_ATTESTED,
			    900000U);
	/* Owners get what the object itself grants, nothing more. */
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &owner,
		PQCP_EDGE_VAULT_PERMISSION_READ, false, T0), 0);
	zassert_equal(pqcp_edge_vault_acl_authorize(&acl, &o, &owner,
		PQCP_EDGE_VAULT_PERMISSION_DELETE, false, T0), -EACCES);

	make_acl(&e, "o1", "bob", PQCP_EDGE_VAULT_PERMISSION_READ);
	e.maximum_uses = 1U;
	zassert_equal(pqcp_edge_vault_acl_put(&acl, &e), 0);
	/* Replacement keeps the generation and accumulated use count. */
	astore[0].use_count = 1U;
	{
		uint32_t gen = astore[0].generation;

		e.maximum_uses = 5U;
		zassert_equal(pqcp_edge_vault_acl_put(&acl, &e), 0);
		zassert_equal(astore[0].generation, gen);
		zassert_equal(astore[0].use_count, 1U);
	}
	make_acl(&e, "o1", "carol", PQCP_EDGE_VAULT_PERMISSION_READ);
	e.expires_at_ms = T0 + 50U;
	zassert_equal(pqcp_edge_vault_acl_put(&acl, &e), 0);
	memcpy(snap, astore, sizeof(snap));
	make_acl(&e, "o1", "dave", PQCP_EDGE_VAULT_PERMISSION_READ);
	zassert_equal(pqcp_edge_vault_acl_put(&acl, &e), -ENOSPC);
	zassert_mem_equal(astore, snap, sizeof(snap));

	zassert_equal(pqcp_edge_vault_acl_expire(&acl, T0 + 50U, &expired),
		      0);
	zassert_equal(expired, 1U);
	zassert_equal(pqcp_edge_vault_acl_remove(&acl, "o1", "carol"),
		      -ENOENT);
	zassert_equal(pqcp_edge_vault_acl_remove(&acl, "o1", "bob"), 0);
	zassert_equal(pqcp_edge_vault_acl_audit(&acl), 0);

	make_acl(&e, "o1", "bob", PQCP_EDGE_VAULT_PERMISSION_READ);
	zassert_equal(pqcp_edge_vault_acl_put(&acl, &e), 0);
	astore[0].maximum_uses = 1U;
	astore[0].use_count = 2U;
	zassert_equal(pqcp_edge_vault_acl_audit(&acl), -EBADMSG);
	astore[0].use_count = 0U;
	astore[1] = astore[0];
	zassert_equal(pqcp_edge_vault_acl_audit(&acl), -EEXIST);
}

/* ------------------------------------------------------------------ */
/* Version store                                                       */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_vault_version verstore[2];
static struct pqcp_edge_vault_version_store vv;

static void version_setup(void)
{
	zassert_equal(pqcp_edge_vault_version_store_init(
		&vv, verstore, ARRAY_SIZE(verstore)), 0);
}

ZTEST(edge_security, test_vault_version_rejects_invalid_arguments)
{
	static struct pqcp_edge_vault_version_store raw;
	struct pqcp_edge_vault_object *o = NULL;
	uint32_t pruned = 0U;

	zassert_equal(pqcp_edge_vault_version_store_init(NULL, verstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_version_store_init(&vv, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_version_store_init(&vv, verstore, 0U),
		      -EINVAL);

	vault_setup();
	create_obj("o1", "alice", "one");
	zassert_equal(pqcp_edge_vault_find(&vs, "o1", &o), 0);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_vault_version_capture(&raw, o, T0, 10U),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_version_restore(&raw, &vs, "o1", 1U,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_version_prune(&raw, T0, &pruned),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_version_store_audit(&raw), -EINVAL);

	version_setup();
	zassert_equal(pqcp_edge_vault_version_capture(&vv, NULL, T0, 10U),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_version_capture(&vv, o, T0, 0U),
		      -EINVAL);
	{
		struct pqcp_edge_vault_object bad = *o;

		bad.occupied = false;
		zassert_equal(pqcp_edge_vault_version_capture(&vv, &bad, T0,
			10U), -EINVAL);
		bad = *o;
		bad.value_length = 0U;
		zassert_equal(pqcp_edge_vault_version_capture(&vv, &bad, T0,
			10U), -EINVAL);
		bad.value_length = PQCP_EDGE_VAULT_VALUE_MAX_BYTES + 1U;
		zassert_equal(pqcp_edge_vault_version_capture(&vv, &bad, T0,
			10U), -EINVAL);
	}
	zassert_equal(pqcp_edge_vault_version_restore(&vv, NULL, "o1", 1U,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_version_restore(&vv, &vs, NULL, 1U,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_version_restore(&vv, &vs, "o1", 0U,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_version_restore(&vv, &vs, "o1", 1U,
		T0), -ENOENT);
	zassert_equal(pqcp_edge_vault_version_prune(&vv, T0, NULL), -EINVAL);
	zassert_equal(vv.captured_count, 0U);
	zassert_equal(pqcp_edge_vault_version_store_audit(&vv), 0);
}

ZTEST(edge_security, test_vault_version_capture_restore_and_prune)
{
	struct pqcp_edge_vault_object *o = NULL;
	uint8_t out[16];
	size_t length = 0U;
	uint32_t pruned = 0U;

	vault_setup();
	version_setup();
	create_obj("o1", "alice", "one");
	zassert_equal(pqcp_edge_vault_find(&vs, "o1", &o), 0);
	zassert_equal(pqcp_edge_vault_version_capture(&vv, o, T0, 1000U), 0);
	/* Same object version cannot be captured twice. */
	zassert_equal(pqcp_edge_vault_version_capture(&vv, o, T0 + 1U,
		1000U), -EALREADY);
	zassert_equal(vv.captured_count, 1U);

	zassert_equal(pqcp_edge_vault_write(&vs, "o1",
		(const uint8_t *)"two", 3U, 1U, T0 + 2U), 0);
	zassert_equal(pqcp_edge_vault_version_restore(&vv, &vs, "o1", 7U,
		T0 + 3U), -ENOENT);
	zassert_equal(pqcp_edge_vault_version_restore(&vv, &vs, "o1", 1U,
		T0 + 3U), 0);
	zassert_equal(o->version, 3U);
	zassert_equal(pqcp_edge_vault_read(&vs, "o1", out, sizeof(out),
		&length, T0 + 4U), 0);
	zassert_equal(length, 3U);
	zassert_mem_equal(out, "one", 3U);
	zassert_equal(pqcp_edge_vault_store_audit(&vs), 0);

	/* Quarantined objects cannot be restored over. */
	o->state = PQCP_EDGE_VAULT_QUARANTINED;
	zassert_equal(pqcp_edge_vault_version_restore(&vv, &vs, "o1", 1U,
		T0 + 5U), -EACCES);
	o->state = PQCP_EDGE_VAULT_ACTIVE;
	/* Unknown target object. */
	{
		struct pqcp_edge_vault_object other;

		make_obj(&other, "ghost", "alice", "x");
		other.occupied = true;
		zassert_equal(pqcp_edge_vault_version_capture(&vv, &other,
			T0, 1000U), 0);
		zassert_equal(pqcp_edge_vault_version_restore(&vv, &vs,
			"ghost", 1U, T0 + 5U), -ENOENT);
	}

	/* Retention lapses: restore refused, prune reaps. */
	zassert_equal(pqcp_edge_vault_version_restore(&vv, &vs, "o1", 1U,
		T0 + 1000U), -EKEYEXPIRED);
	zassert_equal(pqcp_edge_vault_version_prune(&vv, T0 + 999U,
		&pruned), 0);
	zassert_equal(pruned, 0U);
	zassert_equal(pqcp_edge_vault_version_prune(&vv, T0 + 1000U,
		&pruned), 0);
	zassert_equal(pruned, 2U);
	zassert_equal(vv.pruned_count, 2U);
	zassert_equal(pqcp_edge_vault_version_store_audit(&vv), 0);
}

ZTEST(edge_security, test_vault_version_audit_detects_tampering)
{
	struct pqcp_edge_vault_object *o = NULL;

	vault_setup();
	version_setup();
	create_obj("o1", "alice", "one");
	zassert_equal(pqcp_edge_vault_find(&vs, "o1", &o), 0);
	zassert_equal(pqcp_edge_vault_version_capture(&vv, o, T0, 1000U), 0);
	zassert_equal(pqcp_edge_vault_version_store_audit(&vv), 0);
	verstore[0].value[0] ^= 1U;
	zassert_equal(pqcp_edge_vault_version_store_audit(&vv), -EBADMSG);
	verstore[0].value[0] ^= 1U;
	verstore[0].expires_at_ms = verstore[0].created_at_ms;
	zassert_equal(pqcp_edge_vault_version_store_audit(&vv), -EBADMSG);
}

ZTEST(edge_security, test_vault_version_restore_verifies_stored_digest)
{
	struct pqcp_edge_vault_object *o = NULL;
	int ret;

	vault_setup();
	version_setup();
	create_obj("o1", "alice", "one");
	zassert_equal(pqcp_edge_vault_find(&vs, "o1", &o), 0);
	zassert_equal(pqcp_edge_vault_version_capture(&vv, o, T0, 1000U), 0);
	zassert_equal(pqcp_edge_vault_write(&vs, "o1",
		(const uint8_t *)"two", 3U, 1U, T0 + 1U), 0);

	verstore[0].value[0] ^= 0x20U;
	ret = pqcp_edge_vault_version_restore(&vv, &vs, "o1", 1U, T0 + 2U);
	zassert_equal(ret, -EBADMSG);
	zassert_equal(o->version, 2U);
	zassert_equal(pqcp_edge_vault_store_audit(&vs), 0);
	/* Once the retained bytes are intact again the restore works. */
	verstore[0].value[0] ^= 0x20U;
	zassert_equal(pqcp_edge_vault_version_restore(&vv, &vs, "o1", 1U,
		T0 + 3U), 0);
	zassert_equal(o->version, 3U);
	zassert_equal(pqcp_edge_vault_store_audit(&vs), 0);
}

ZTEST(edge_security, test_vault_version_capacity_keeps_retained_history)
{
	struct pqcp_edge_vault_object o;
	int ret;

	version_setup();
	make_obj(&o, "o1", "alice", "v");
	o.occupied = true;
	for (uint64_t v = 1U; v <= 2U; ++v) {
		o.version = v;
		zassert_equal(pqcp_edge_vault_version_capture(&vv, &o, T0 + v,
			100000U), 0);
	}
	o.version = 3U;
	ret = pqcp_edge_vault_version_capture(&vv, &o, T0 + 3U, 100000U);
	zassert_equal(ret, -ENOSPC);
	/* Both retained versions are intact. */
	zassert_equal(verstore[0].object_version, 1U);
	zassert_equal(verstore[1].object_version, 2U);
	/* An expired version may be reclaimed. */
	ret = pqcp_edge_vault_version_capture(&vv, &o, T0 + 100001U + 1U,
		100000U);
	zassert_equal(ret, 0);
	zassert_equal(verstore[0].object_version, 3U);
	zassert_equal(verstore[1].object_version, 2U);
}

/* ------------------------------------------------------------------ */
/* Vault leases                                                        */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_vault_lease lstore[2];
static struct pqcp_edge_vault_lease_manager lm;

static void lease_setup(void)
{
	zassert_equal(pqcp_edge_vault_lease_manager_init(
		&lm, lstore, ARRAY_SIZE(lstore)), 0);
}

ZTEST(edge_security, test_vault_lease_rejects_invalid_arguments)
{
	static struct pqcp_edge_vault_lease_manager raw;
	struct pqcp_edge_vault_lease *lease = (void *)0x1;
	uint32_t expired = 0U;
	const uint32_t read = PQCP_EDGE_VAULT_PERMISSION_READ;

	zassert_equal(pqcp_edge_vault_lease_manager_init(NULL, lstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_manager_init(&lm, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_manager_init(&lm, lstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_vault_lease_issue(&raw, "o", "p", read, 1U,
		T0, T0 + 10U, 1U, &lease), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_authorize(&raw, 1U, "o", "p",
		read, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_revoke(&raw, 1U), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_expire(&raw, T0, &expired),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_manager_audit(&raw), -EINVAL);

	lease_setup();
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, NULL, "p", read, 1U,
		T0, T0 + 10U, 1U, &lease), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, "o", "", read, 1U,
		T0, T0 + 10U, 1U, &lease), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, "o", "p", 0U, 1U, T0,
		T0 + 10U, 1U, &lease), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, "o", "p", 1U << 15,
		1U, T0, T0 + 10U, 1U, &lease), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, "o", "p", read, 0U,
		T0, T0 + 10U, 1U, &lease), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, "o", "p", read, 1U,
		T0, T0, 1U, &lease), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, "o", "p", read, 1U,
		T0, T0 + 10U, 0U, &lease), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, "o", "p", read, 1U,
		T0, T0 + 10U, 1U, NULL), -EINVAL);
	zassert_equal(lm.issued_count, 0U);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, 0U, "o", "p", read,
		1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, 1U, NULL, "p",
		read, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, 1U, "o", "p", 0U,
		1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, 1U, "o", "p",
		read, 0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, 9U, "o", "p",
		read, 1U, T0), -ENOENT);
	zassert_equal(pqcp_edge_vault_lease_revoke(&lm, 0U), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_revoke(&lm, 9U), -ENOENT);
	zassert_equal(pqcp_edge_vault_lease_expire(&lm, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_vault_lease_manager_audit(&lm), 0);
}

ZTEST(edge_security, test_vault_lease_scope_budget_and_revocation)
{
	struct pqcp_edge_vault_lease *l = NULL;
	const uint32_t read = PQCP_EDGE_VAULT_PERMISSION_READ;
	const uint32_t write = PQCP_EDGE_VAULT_PERMISSION_WRITE;
	uint64_t id;

	lease_setup();
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, "o1", "bob", read, 3U,
		T0, T0 + 1000U, 2U, &l), 0);
	id = l->lease_id;
	zassert_equal(lm.issued_count, 1U);

	/* Every scope dimension must match exactly. */
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, id, "o1", "bob",
		read, 4U, T0 + 1U), -ESTALE);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, id, "o2", "bob",
		read, 3U, T0 + 1U), -EACCES);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, id, "o1", "eve",
		read, 3U, T0 + 1U), -EACCES);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, id, "o1", "bob",
		write, 3U, T0 + 1U), -EACCES);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, id, "o1", "bob",
		read | write, 3U, T0 + 1U), -EACCES);
	zassert_equal(l->use_count, 0U);
	zassert_equal(lm.rejected_count, 5U);

	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, id, "o1", "bob",
		read, 3U, T0 + 1U), 0);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, id, "o1", "bob",
		read, 3U, T0 + 2U), 0);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, id, "o1", "bob",
		read, 3U, T0 + 3U), -EDQUOT);
	zassert_equal(l->use_count, 2U);

	zassert_equal(pqcp_edge_vault_lease_revoke(&lm, id), 0);
	zassert_equal(pqcp_edge_vault_lease_revoke(&lm, id), -EALREADY);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, id, "o1", "bob",
		read, 3U, T0 + 4U), -EKEYREVOKED);
	zassert_equal(pqcp_edge_vault_lease_manager_audit(&lm), 0);
}

ZTEST(edge_security, test_vault_lease_expiry_capacity_and_audit)
{
	struct pqcp_edge_vault_lease *l1 = NULL;
	struct pqcp_edge_vault_lease *l2 = NULL;
	struct pqcp_edge_vault_lease *l3 = (void *)0x1;
	const uint32_t read = PQCP_EDGE_VAULT_PERMISSION_READ;
	uint32_t expired = 0U;
	uint64_t id1;

	lease_setup();
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, "o1", "bob", read, 1U,
		T0, T0 + 100U, 5U, &l1), 0);
	id1 = l1->lease_id;
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, "o2", "bob", read, 1U,
		T0, T0 + 1000U, 5U, &l2), 0);
	/* All live: new lease is refused and nothing is displaced. */
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, "o3", "bob", read, 1U,
		T0, T0 + 1000U, 5U, &l3), -ENOSPC);
	zassert_is_null(l3);
	zassert_equal(lm.rejected_count, 1U);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, id1, "o1", "bob",
		read, 1U, T0 + 100U), -EKEYEXPIRED);

	zassert_equal(pqcp_edge_vault_lease_expire(&lm, T0 + 100U,
						   &expired), 0);
	zassert_equal(expired, 1U);
	zassert_equal(pqcp_edge_vault_lease_authorize(&lm, id1, "o1", "bob",
		read, 1U, T0 + 50U), -EKEYREVOKED);
	/* The reaped slot is reusable. */
	zassert_equal(pqcp_edge_vault_lease_issue(&lm, "o3", "bob", read, 1U,
		T0 + 101U, T0 + 1000U, 5U, &l3), 0);
	zassert_true(l3->lease_id > id1);
	zassert_equal(pqcp_edge_vault_lease_manager_audit(&lm), 0);

	l3->permissions ^= PQCP_EDGE_VAULT_PERMISSION_WRITE;
	zassert_equal(pqcp_edge_vault_lease_manager_audit(&lm), -EBADMSG);
	l3->permissions ^= PQCP_EDGE_VAULT_PERMISSION_WRITE;
	l3->use_count = l3->maximum_uses + 1U;
	zassert_equal(pqcp_edge_vault_lease_manager_audit(&lm), -EBADMSG);
}

/* ------------------------------------------------------------------ */
/* Journal, snapshots and audit export                                 */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_vault_journal_entry jstore[3];
static struct pqcp_edge_vault_journal journal;

static void journal_setup(void)
{
	zassert_equal(pqcp_edge_vault_journal_init(
		&journal, jstore, ARRAY_SIZE(jstore)), 0);
}

static void jappend(uint32_t n)
{
	const uint8_t payload[2] = { (uint8_t)n, 0x5aU };

	zassert_equal(pqcp_edge_vault_journal_append(&journal,
		PQCP_EDGE_VAULT_JOURNAL_UPDATE, "o1", "alice", 0, payload,
		sizeof(payload), T0 + n), 0);
}

ZTEST(edge_security, test_journal_rejects_invalid_arguments)
{
	static struct pqcp_edge_vault_journal raw;
	struct pqcp_edge_vault_journal_entry e;
	const uint8_t payload[1] = { 1 };
	char unterminated[PQCP_EDGE_ACTOR_MAX_CHARS];

	zassert_equal(pqcp_edge_vault_journal_init(NULL, jstore, 3U),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_journal_init(&journal, NULL, 3U),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_journal_init(&journal, jstore, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_vault_journal_append(&raw,
		PQCP_EDGE_VAULT_JOURNAL_READ, "o", "a", 0, payload, 1U, T0),
		-EINVAL);
	zassert_equal(pqcp_edge_vault_journal_find(&raw, 1U, &e), -EINVAL);
	zassert_equal(pqcp_edge_vault_journal_verify(&raw), -EINVAL);
	zassert_equal(pqcp_edge_vault_journal_verify(NULL), -EINVAL);

	journal_setup();
	memset(unterminated, 'x', sizeof(unterminated));
	zassert_equal(pqcp_edge_vault_journal_append(&journal,
		(enum pqcp_edge_vault_journal_event)99, "o", "a", 0, payload,
		1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_journal_append(&journal,
		(enum pqcp_edge_vault_journal_event)-1, "o", "a", 0, payload,
		1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_journal_append(&journal,
		PQCP_EDGE_VAULT_JOURNAL_READ, NULL, "a", 0, payload, 1U, T0),
		-EINVAL);
	zassert_equal(pqcp_edge_vault_journal_append(&journal,
		PQCP_EDGE_VAULT_JOURNAL_READ, "o", "", 0, payload, 1U, T0),
		-EINVAL);
	zassert_equal(pqcp_edge_vault_journal_append(&journal,
		PQCP_EDGE_VAULT_JOURNAL_READ, "o", unterminated, 0, payload,
		1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_vault_journal_append(&journal,
		PQCP_EDGE_VAULT_JOURNAL_READ, "o", "a", 0, NULL, 1U, T0),
		-EINVAL);
	zassert_equal(journal.count, 0U);
	zassert_equal(journal.next_sequence, 1U);
	zassert_equal(pqcp_edge_vault_journal_find(&journal, 0U, &e),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_journal_find(&journal, 1U, NULL),
		      -EINVAL);
	zassert_equal(pqcp_edge_vault_journal_find(&journal, 1U, &e),
		      -ENOENT);
	zassert_equal(pqcp_edge_vault_journal_verify(&journal), 0);
}

ZTEST(edge_security, test_journal_hash_chain_and_wraparound)
{
	struct pqcp_edge_vault_journal_entry e1;
	struct pqcp_edge_vault_journal_entry e2;
	uint8_t head[PQCP_EDGE_DIGEST_BYTES];
	uint64_t first;

	journal_setup();
	jappend(1U);
	jappend(2U);
	first = jstore[0].sequence;
	zassert_equal(pqcp_edge_vault_journal_find(&journal, first, &e1), 0);
	zassert_equal(pqcp_edge_vault_journal_find(&journal, first + 1U,
		&e2), 0);
	zassert_equal(e1.sequence, first);
	zassert_equal(e2.sequence, first + 1U);
	zassert_equal(e1.event, PQCP_EDGE_VAULT_JOURNAL_UPDATE);
	zassert_str_equal(e1.object_id, "o1");
	zassert_str_equal(e1.actor_id, "alice");
	zassert_true(pqcp_edge_internal_all_zero(e1.previous_digest,
		sizeof(e1.previous_digest)));
	zassert_mem_equal(e2.previous_digest, e1.entry_digest,
			  sizeof(e1.entry_digest));
	zassert_mem_equal(journal.chain_head, e2.entry_digest,
			  sizeof(e2.entry_digest));
	zassert_equal(pqcp_edge_vault_journal_verify(&journal), 0);
	memcpy(head, journal.chain_head, sizeof(head));

	/* The ring overwrites the oldest entry and counts the drop. */
	jappend(3U);
	jappend(4U);
	jappend(5U);
	zassert_equal(journal.count, 3U);
	zassert_equal(journal.dropped_count, 2U);
	zassert_equal(pqcp_edge_vault_journal_find(&journal, first, &e1),
		      -ENOENT);
	zassert_equal(pqcp_edge_vault_journal_find(&journal, first + 4U,
		&e1), 0);
	zassert_true(memcmp(head, journal.chain_head, sizeof(head)) != 0);
	zassert_equal(pqcp_edge_vault_journal_verify(&journal), 0);
}

ZTEST(edge_security, test_journal_first_sequence_is_one)
{
	journal_setup();
	jappend(1U);
	zassert_equal(jstore[0].sequence, 1U);
}

ZTEST(edge_security, test_journal_verify_detects_tampering)
{
	journal_setup();
	jappend(1U);
	jappend(2U);
	jappend(3U);
	zassert_equal(pqcp_edge_vault_journal_verify(&journal), 0);

	jstore[1].result = -EIO;
	zassert_equal(pqcp_edge_vault_journal_verify(&journal), -EBADMSG);
	jstore[1].result = 0;
	zassert_equal(pqcp_edge_vault_journal_verify(&journal), 0);

	/* Truncation of a middle entry breaks sequence continuity. */
	memset(&jstore[1], 0, sizeof(jstore[1]));
	zassert_equal(pqcp_edge_vault_journal_verify(&journal), -EBADMSG);

	/* Forged head. */
	journal_setup();
	jappend(1U);
	journal.chain_head[0] ^= 1U;
	zassert_equal(pqcp_edge_vault_journal_verify(&journal), -EBADMSG);
	journal.chain_head[0] ^= 1U;
	/* Rewriting an entry and recomputing nothing else is detected. */
	jstore[0].timestamp_ms += 1U;
	zassert_equal(pqcp_edge_vault_journal_verify(&journal), -EBADMSG);
}

static struct pqcp_edge_vault_snapshot snstore[2];
static struct pqcp_edge_snapshot_manager sm;

ZTEST(edge_security, test_snapshot_rejects_invalid_arguments)
{
	static struct pqcp_edge_snapshot_manager raw;
	struct pqcp_edge_vault_snapshot *snap = (void *)0x1;

	zassert_equal(pqcp_edge_snapshot_manager_init(NULL, snstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_snapshot_manager_init(&sm, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_snapshot_manager_init(&sm, snstore, 0U),
		      -EINVAL);

	vault_setup();
	journal_setup();
	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_snapshot_capture(&raw, &vs, &journal, T0,
		&snap), -EINVAL);
	zassert_equal(pqcp_edge_snapshot_verify(&raw, 1U), -EINVAL);
	zassert_equal(pqcp_edge_snapshot_manager_audit(&raw), -EINVAL);

	zassert_equal(pqcp_edge_snapshot_manager_init(&sm, snstore, 2U), 0);
	zassert_equal(pqcp_edge_snapshot_capture(&sm, NULL, &journal, T0,
		&snap), -EINVAL);
	zassert_equal(pqcp_edge_snapshot_capture(&sm, &vs, NULL, T0, &snap),
		      -EINVAL);
	zassert_equal(pqcp_edge_snapshot_capture(&sm, &vs, &journal, T0,
		NULL), -EINVAL);
	{
		static struct pqcp_edge_vault_store uninit;

		memset(&uninit, 0, sizeof(uninit));
		zassert_equal(pqcp_edge_snapshot_capture(&sm, &uninit,
			&journal, T0, &snap), -EINVAL);
	}
	zassert_equal(pqcp_edge_snapshot_verify(&sm, 0U), -EINVAL);
	zassert_equal(pqcp_edge_snapshot_verify(&sm, 7U), -ENOENT);
	zassert_equal(sm.captured_count, 0U);
	zassert_equal(pqcp_edge_snapshot_manager_audit(&sm), 0);
}

ZTEST(edge_security, test_snapshot_binds_store_and_journal_state)
{
	struct pqcp_edge_vault_snapshot *s1 = NULL;
	struct pqcp_edge_vault_snapshot *s2 = NULL;
	struct pqcp_edge_vault_snapshot *s3 = NULL;
	uint8_t first_digest[PQCP_EDGE_DIGEST_BYTES];
	uint64_t s1_id;

	vault_setup();
	journal_setup();
	zassert_equal(pqcp_edge_snapshot_manager_init(&sm, snstore, 2U), 0);
	create_obj("o1", "alice", "aaa");
	jappend(1U);

	zassert_equal(pqcp_edge_snapshot_capture(&sm, &vs, &journal, T0,
		&s1), 0);
	s1_id = s1->snapshot_id;
	zassert_equal(s1->object_count, 1U);
	zassert_equal(s1->highest_object_version, 1U);
	zassert_mem_equal(s1->journal_head, journal.chain_head,
			  PQCP_EDGE_DIGEST_BYTES);
	zassert_equal(pqcp_edge_snapshot_verify(&sm, s1_id), 0);
	memcpy(first_digest, s1->store_digest, sizeof(first_digest));

	/* State change shows up in the next snapshot, not the first. */
	zassert_equal(pqcp_edge_vault_write(&vs, "o1",
		(const uint8_t *)"bbb", 3U, 1U, T0 + 5U), 0);
	jappend(2U);
	zassert_equal(pqcp_edge_snapshot_capture(&sm, &vs, &journal, T0 + 5U,
		&s2), 0);
	zassert_true(memcmp(first_digest, s2->store_digest,
			    sizeof(first_digest)) != 0);
	zassert_equal(s2->highest_object_version, 2U);
	zassert_true(memcmp(s1->journal_head, s2->journal_head,
			    PQCP_EDGE_DIGEST_BYTES) != 0);
	zassert_mem_equal(s1->store_digest, first_digest, sizeof(first_digest));

	/* Full manager recycles the oldest checkpoint. */
	zassert_equal(pqcp_edge_snapshot_capture(&sm, &vs, &journal, T0 + 9U,
		&s3), 0);
	zassert_equal(pqcp_edge_snapshot_verify(&sm, s1_id), -ENOENT);
	zassert_equal(sm.captured_count, 3U);
	zassert_equal(pqcp_edge_snapshot_manager_audit(&sm), 0);

	/* Tampering with a stored checkpoint is detected. */
	s3->object_count += 1U;
	zassert_equal(pqcp_edge_snapshot_verify(&sm, s3->snapshot_id),
		      -EBADMSG);
	zassert_equal(pqcp_edge_snapshot_manager_audit(&sm), -EBADMSG);
	s3->object_count -= 1U;
	snstore[1] = snstore[0];
	zassert_equal(pqcp_edge_snapshot_manager_audit(&sm), -EEXIST);
}

/* ------------------------------------------------------------------ */
/* Replication                                                         */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_replica_record rpl_store[2];
static struct pqcp_edge_replication_manager rm;

static void replication_setup(void)
{
	zassert_equal(pqcp_edge_replication_manager_init(
		&rm, rpl_store, ARRAY_SIZE(rpl_store)), 0);
}

static void obj_for_replication(struct pqcp_edge_vault_object *o,
				const char *id, uint8_t digest_seed)
{
	make_obj(o, id, "alice", "v");
	o->occupied = true;
	edge_digest(o->object_digest, digest_seed);
}

ZTEST(edge_security, test_replication_rejects_invalid_arguments)
{
	static struct pqcp_edge_replication_manager raw;
	struct pqcp_edge_vault_object o;
	struct pqcp_edge_replica_record *r = (void *)0x1;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];

	obj_for_replication(&o, "o1", 1U);
	edge_digest(digest, 1U);
	zassert_equal(pqcp_edge_replication_manager_init(NULL, rpl_store, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_replication_manager_init(&rm, NULL, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_replication_manager_init(&rm, rpl_store, 0U),
		      -EINVAL);

	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_replication_schedule(&raw, &o, "t", T0, 3U,
		&r), -EINVAL);
	zassert_equal(pqcp_edge_replication_next(&raw, T0, &r), -EINVAL);
	zassert_equal(pqcp_edge_replication_complete(&raw, 1U, 0, digest,
		T0), -EINVAL);
	zassert_equal(pqcp_edge_replication_retry(&raw, 1U, T0), -EINVAL);
	zassert_equal(pqcp_edge_replication_manager_audit(&raw), -EINVAL);

	replication_setup();
	zassert_equal(pqcp_edge_replication_schedule(&rm, NULL, "t", T0, 3U,
		&r), -EINVAL);
	zassert_equal(pqcp_edge_replication_schedule(&rm, &o, NULL, T0, 3U,
		&r), -EINVAL);
	zassert_equal(pqcp_edge_replication_schedule(&rm, &o, "", T0, 3U,
		&r), -EINVAL);
	zassert_equal(pqcp_edge_replication_schedule(&rm, &o, "t", T0, 0U,
		&r), -EINVAL);
	zassert_equal(pqcp_edge_replication_schedule(&rm, &o, "t", T0, 3U,
		NULL), -EINVAL);
	o.occupied = false;
	zassert_equal(pqcp_edge_replication_schedule(&rm, &o, "t", T0, 3U,
		&r), -EINVAL);
	zassert_equal(pqcp_edge_replication_next(&rm, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_replication_next(&rm, T0, &r), -EAGAIN);
	zassert_is_null(r);
	zassert_equal(pqcp_edge_replication_complete(&rm, 0U, 0, digest, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_replication_complete(&rm, 1U, 0, NULL, T0),
		      -EINVAL);
	zassert_equal(pqcp_edge_replication_complete(&rm, 9U, 0, digest, T0),
		      -ENOENT);
	zassert_equal(pqcp_edge_replication_retry(&rm, 0U, T0), -EINVAL);
	zassert_equal(pqcp_edge_replication_retry(&rm, 9U, T0), -ENOENT);
	zassert_equal(pqcp_edge_replication_manager_audit(&rm), 0);
}

ZTEST(edge_security, test_replication_digest_bound_completion)
{
	struct pqcp_edge_vault_object o;
	struct pqcp_edge_replica_record *r = NULL;
	struct pqcp_edge_replica_record *dup = NULL;
	struct pqcp_edge_replica_record *next = NULL;
	uint8_t good[PQCP_EDGE_DIGEST_BYTES];
	uint8_t bad[PQCP_EDGE_DIGEST_BYTES];
	uint64_t id;

	replication_setup();
	obj_for_replication(&o, "o1", 4U);
	edge_digest(good, 4U);
	edge_digest(bad, 5U);

	zassert_equal(pqcp_edge_replication_schedule(&rm, &o, "peer", T0, 3U,
		&r), 0);
	id = r->replication_id;
	zassert_equal(r->state, PQCP_EDGE_REPLICA_PENDING);
	/* Same object/version/target is not scheduled twice. */
	zassert_equal(pqcp_edge_replication_schedule(&rm, &o, "peer", T0 + 1U,
		3U, &dup), -EALREADY);
	zassert_equal(dup, r);
	/* Completion requires a transfer to be in progress. */
	zassert_equal(pqcp_edge_replication_complete(&rm, id, 0, good,
		T0 + 1U), -EALREADY);
	zassert_equal(r->state, PQCP_EDGE_REPLICA_PENDING);

	zassert_equal(pqcp_edge_replication_next(&rm, T0 + 1U, &next), 0);
	zassert_equal(next, r);
	zassert_equal(r->state, PQCP_EDGE_REPLICA_TRANSFERRING);
	zassert_equal(r->attempts, 1U);
	zassert_equal(pqcp_edge_replication_next(&rm, T0 + 1U, &next),
		      -EAGAIN);

	/* A target reporting success with the wrong digest is a conflict. */
	zassert_equal(pqcp_edge_replication_complete(&rm, id, 0, bad,
		T0 + 2U), -EBADMSG);
	zassert_equal(r->state, PQCP_EDGE_REPLICA_CONFLICT);
	zassert_equal(rm.success_count, 0U);
	zassert_equal(rm.failure_count, 1U);
	/* Conflicts are terminal: never picked up again. */
	zassert_equal(pqcp_edge_replication_next(&rm, T0 + 999999U, &next),
		      -EAGAIN);
	zassert_equal(pqcp_edge_replication_retry(&rm, id, T0 + 3U),
		      -EALREADY);

	/* A new object version replicates and applies with the right digest. */
	o.version = 2U;
	zassert_equal(pqcp_edge_replication_schedule(&rm, &o, "peer", T0 + 5U,
		3U, &r), 0);
	zassert_equal(pqcp_edge_replication_next(&rm, T0 + 5U, &next), 0);
	zassert_equal(pqcp_edge_replication_complete(&rm, r->replication_id,
		0, good, T0 + 6U), 0);
	zassert_equal(r->state, PQCP_EDGE_REPLICA_APPLIED);
	zassert_equal(rm.success_count, 1U);
	zassert_equal(pqcp_edge_replication_manager_audit(&rm), 0);
}

ZTEST(edge_security, test_replication_retry_budget)
{
	struct pqcp_edge_vault_object o;
	struct pqcp_edge_replica_record *r = NULL;
	struct pqcp_edge_replica_record *next = NULL;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];

	replication_setup();
	obj_for_replication(&o, "o1", 4U);
	edge_digest(digest, 4U);
	zassert_equal(pqcp_edge_replication_schedule(&rm, &o, "peer", T0, 2U,
		&r), 0);

	zassert_equal(pqcp_edge_replication_next(&rm, T0, &next), 0);
	zassert_equal(pqcp_edge_replication_complete(&rm, r->replication_id,
		-EIO, digest, T0 + 10U), 0);
	zassert_equal(r->state, PQCP_EDGE_REPLICA_FAILED);
	zassert_equal(r->retry_at_ms, T0 + 10U + 250U);
	zassert_equal(r->result, -EIO);
	zassert_equal(pqcp_edge_replication_next(&rm, T0 + 259U, &next),
		      -EAGAIN);
	zassert_equal(pqcp_edge_replication_next(&rm, T0 + 260U, &next), 0);
	zassert_equal(r->attempts, 2U);

	/* The last attempt fails terminally; neither next nor retry revive it. */
	zassert_equal(pqcp_edge_replication_complete(&rm, r->replication_id,
		-EIO, digest, T0 + 300U), 0);
	zassert_equal(r->state, PQCP_EDGE_REPLICA_FAILED);
	zassert_equal(rm.failure_count, 1U);
	zassert_equal(pqcp_edge_replication_next(&rm, T0 + 999999U, &next),
		      -EAGAIN);
	zassert_equal(pqcp_edge_replication_retry(&rm, r->replication_id,
		T0 + 400U), -EALREADY);
	zassert_equal(r->state, PQCP_EDGE_REPLICA_FAILED);

	r->attempts = r->maximum_attempts + 1U;
	zassert_equal(pqcp_edge_replication_manager_audit(&rm), -EBADMSG);
	r->attempts = 1U;
	memset(r->object_digest, 0, sizeof(r->object_digest));
	zassert_equal(pqcp_edge_replication_manager_audit(&rm), -EBADMSG);
}

ZTEST(edge_security, test_replication_manual_retry_and_capacity)
{
	struct pqcp_edge_vault_object o;
	struct pqcp_edge_replica_record *r = NULL;
	struct pqcp_edge_replica_record *r2 = NULL;
	struct pqcp_edge_replica_record *next = NULL;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];

	replication_setup();
	obj_for_replication(&o, "o1", 4U);
	edge_digest(digest, 4U);
	zassert_equal(pqcp_edge_replication_schedule(&rm, &o, "a", T0, 3U,
		&r), 0);
	zassert_equal(pqcp_edge_replication_schedule(&rm, &o, "b", T0 + 1U,
		3U, &r2), 0);
	/* Table full of live work: refuse, keep both. */
	{
		struct pqcp_edge_replica_record *r3 = (void *)0x1;

		zassert_equal(pqcp_edge_replication_schedule(&rm, &o, "c",
			T0 + 2U, 3U, &r3), -ENOSPC);
		zassert_is_null(r3);
	}
	/* Oldest scheduled is served first. */
	zassert_equal(pqcp_edge_replication_next(&rm, T0 + 2U, &next), 0);
	zassert_str_equal(next->target_id, "a");
	zassert_equal(pqcp_edge_replication_complete(&rm, next->replication_id,
		-EIO, digest, T0 + 3U), 0);
	/* Operator override reschedules a failed replication immediately. */
	zassert_equal(pqcp_edge_replication_retry(&rm, r->replication_id,
		T0 + 3U), 0);
	zassert_equal(r->state, PQCP_EDGE_REPLICA_PENDING);
	zassert_equal(pqcp_edge_replication_retry(&rm, r->replication_id,
		T0 + 3U), -EALREADY);
}

ZTEST(edge_security, test_replication_failed_with_retries_is_not_evicted)
{
	struct pqcp_edge_vault_object o;
	struct pqcp_edge_replica_record *r = NULL;
	struct pqcp_edge_replica_record *r2 = NULL;
	struct pqcp_edge_replica_record *next = NULL;
	uint8_t digest[PQCP_EDGE_DIGEST_BYTES];
	int ret;

	zassert_equal(pqcp_edge_replication_manager_init(&rm, rpl_store, 1U),
		      0);
	obj_for_replication(&o, "o1", 4U);
	edge_digest(digest, 4U);
	zassert_equal(pqcp_edge_replication_schedule(&rm, &o, "a", T0, 5U,
		&r), 0);
	zassert_equal(pqcp_edge_replication_next(&rm, T0, &next), 0);
	zassert_equal(pqcp_edge_replication_complete(&rm, r->replication_id,
		-EIO, digest, T0 + 1U), 0);
	/* One attempt of five used; a retry is still owed. */
	ret = pqcp_edge_replication_schedule(&rm, &o, "b", T0 + 2U, 5U, &r2);
	zassert_equal(ret, -ENOSPC);
	/* The pending retry is intact and still schedulable. */
	zassert_equal(r->state, PQCP_EDGE_REPLICA_FAILED);
	zassert_equal(r->attempts, 1U);
	zassert_equal(pqcp_edge_replication_retry(&rm, r->replication_id,
		T0 + 2U), 0);
	zassert_equal(r->state, PQCP_EDGE_REPLICA_PENDING);
	zassert_equal(pqcp_edge_replication_manager_audit(&rm), 0);
}

/* ------------------------------------------------------------------ */
/* Audit exporter                                                      */
/* ------------------------------------------------------------------ */

static struct pqcp_edge_export_cursor xstore[2];
static struct pqcp_edge_audit_exporter ex;

static void exporter_setup(void)
{
	zassert_equal(pqcp_edge_audit_exporter_init(
		&ex, xstore, ARRAY_SIZE(xstore)), 0);
}

ZTEST(edge_security, test_audit_exporter_rejects_invalid_arguments)
{
	static struct pqcp_edge_audit_exporter raw;
	struct pqcp_edge_export_cursor *c = (void *)0x1;
	struct pqcp_edge_export_batch b;
	uint32_t expired = 0U;

	zassert_equal(pqcp_edge_audit_exporter_init(NULL, xstore, 2U),
		      -EINVAL);
	zassert_equal(pqcp_edge_audit_exporter_init(&ex, NULL, 2U), -EINVAL);
	zassert_equal(pqcp_edge_audit_exporter_init(&ex, xstore, 0U),
		      -EINVAL);

	journal_setup();
	memset(&raw, 0, sizeof(raw));
	zassert_equal(pqcp_edge_audit_export_open(&raw, "c", 1U, T0, 10U,
		&c), -EINVAL);
	zassert_equal(pqcp_edge_audit_export_batch(&raw, &journal, 1U, 1U,
		T0, &b), -EINVAL);
	zassert_equal(pqcp_edge_audit_export_acknowledge(&raw, 1U, 1U),
		      -EINVAL);
	zassert_equal(pqcp_edge_audit_export_expire(&raw, T0, &expired),
		      -EINVAL);
	zassert_equal(pqcp_edge_audit_exporter_audit(&raw), -EINVAL);

	exporter_setup();
	zassert_equal(pqcp_edge_audit_export_open(&ex, NULL, 1U, T0, 10U, &c),
		      -EINVAL);
	zassert_equal(pqcp_edge_audit_export_open(&ex, "", 1U, T0, 10U, &c),
		      -EINVAL);
	zassert_equal(pqcp_edge_audit_export_open(&ex, "c", 0U, T0, 10U, &c),
		      -EINVAL);
	zassert_equal(pqcp_edge_audit_export_open(&ex, "c", 1U, T0, 0U, &c),
		      -EINVAL);
	zassert_equal(pqcp_edge_audit_export_open(&ex, "c", 1U, T0, 10U,
		NULL), -EINVAL);
	zassert_false(xstore[0].occupied);
	zassert_equal(pqcp_edge_audit_export_batch(&ex, NULL, 1U, 1U, T0,
		&b), -EINVAL);
	zassert_equal(pqcp_edge_audit_export_batch(&ex, &journal, 0U, 1U, T0,
		&b), -EINVAL);
	zassert_equal(pqcp_edge_audit_export_batch(&ex, &journal, 1U, 0U, T0,
		&b), -EINVAL);
	zassert_equal(pqcp_edge_audit_export_batch(&ex, &journal, 1U, 1U, T0,
		NULL), -EINVAL);
	zassert_equal(pqcp_edge_audit_export_batch(&ex, &journal, 9U, 1U, T0,
		&b), -ENOENT);
	zassert_equal(pqcp_edge_audit_export_acknowledge(&ex, 0U, 1U),
		      -EINVAL);
	zassert_equal(pqcp_edge_audit_export_acknowledge(&ex, 1U, 0U),
		      -EINVAL);
	zassert_equal(pqcp_edge_audit_export_acknowledge(&ex, 9U, 1U),
		      -ENOENT);
	zassert_equal(pqcp_edge_audit_export_expire(&ex, T0, NULL), -EINVAL);
	zassert_equal(pqcp_edge_audit_exporter_audit(&ex), 0);
}

ZTEST(edge_security, test_audit_exporter_resumable_batches)
{
	struct pqcp_edge_export_cursor *c = NULL;
	struct pqcp_edge_export_batch b1;
	struct pqcp_edge_export_batch b1_again;
	struct pqcp_edge_export_batch b2;
	uint32_t expired = 0U;
	uint64_t first;

	journal_setup();
	exporter_setup();
	jappend(1U);
	jappend(2U);
	jappend(3U);
	first = jstore[0].sequence;

	zassert_equal(pqcp_edge_audit_export_open(&ex, "uplink", first, T0,
		1000U, &c), 0);
	zassert_equal(c->next_sequence, first);
	zassert_equal(c->acknowledged_sequence, first - 1U);
	zassert_equal(pqcp_edge_audit_export_batch(&ex, &journal,
		c->cursor_id, 2U, T0 + 1U, &b1), 0);
	zassert_equal(b1.first_sequence, first);
	zassert_equal(b1.last_sequence, first + 1U);
	zassert_equal(b1.record_count, 2U);
	/* Without an acknowledgement the same batch is replayed exactly. */
	zassert_equal(pqcp_edge_audit_export_batch(&ex, &journal,
		c->cursor_id, 2U, T0 + 2U, &b1_again), 0);
	zassert_mem_equal(&b1, &b1_again, sizeof(b1));

	zassert_equal(pqcp_edge_audit_export_acknowledge(&ex, c->cursor_id,
		first + 1U), 0);
	zassert_equal(c->next_sequence, first + 2U);
	/* Acknowledgements cannot move backwards. */
	zassert_equal(pqcp_edge_audit_export_acknowledge(&ex, c->cursor_id,
		first + 1U), -ESTALE);
	zassert_equal(pqcp_edge_audit_export_acknowledge(&ex, c->cursor_id,
		first), -ESTALE);
	zassert_equal(c->next_sequence, first + 2U);

	zassert_equal(pqcp_edge_audit_export_batch(&ex, &journal,
		c->cursor_id, 10U, T0 + 3U, &b2), 0);
	zassert_equal(b2.first_sequence, first + 2U);
	zassert_equal(b2.record_count, 1U);
	zassert_true(memcmp(b1.batch_digest, b2.batch_digest,
			    sizeof(b1.batch_digest)) != 0);
	zassert_equal(pqcp_edge_audit_export_acknowledge(&ex, c->cursor_id,
		first + 2U), 0);
	/* Caught up: nothing to export. */
	zassert_equal(pqcp_edge_audit_export_batch(&ex, &journal,
		c->cursor_id, 10U, T0 + 4U, &b2), -EAGAIN);
	zassert_equal(ex.exported_records, 5U);
	zassert_equal(pqcp_edge_audit_exporter_audit(&ex), 0);

	/* Expired cursors refuse export and are reaped. */
	zassert_equal(pqcp_edge_audit_export_batch(&ex, &journal,
		c->cursor_id, 10U, T0 + 1000U, &b2), -ETIMEDOUT);
	zassert_equal(pqcp_edge_audit_export_expire(&ex, T0 + 999U,
		&expired), 0);
	zassert_equal(expired, 0U);
	zassert_equal(pqcp_edge_audit_export_expire(&ex, T0 + 1000U,
		&expired), 0);
	zassert_equal(expired, 1U);
	zassert_false(xstore[0].occupied);
}

ZTEST(edge_security, test_audit_exporter_capacity_and_audit)
{
	struct pqcp_edge_export_cursor *c1 = NULL;
	struct pqcp_edge_export_cursor *c2 = NULL;
	struct pqcp_edge_export_cursor *c3 = (void *)0x1;

	exporter_setup();
	zassert_equal(pqcp_edge_audit_export_open(&ex, "a", 1U, T0, 100U,
		&c1), 0);
	zassert_equal(pqcp_edge_audit_export_open(&ex, "b", 5U, T0, 100U,
		&c2), 0);
	zassert_equal(c2->acknowledged_sequence, 4U);
	zassert_equal(pqcp_edge_audit_export_open(&ex, "c", 1U, T0, 100U,
		&c3), -ENOSPC);
	zassert_is_null(c3);
	zassert_equal(pqcp_edge_audit_exporter_audit(&ex), 0);
	c1->acknowledged_sequence = c1->next_sequence;
	zassert_equal(pqcp_edge_audit_exporter_audit(&ex), -EBADMSG);
	c1->acknowledged_sequence = 0U;
	c1->consumer_id[0] = '\0';
	zassert_equal(pqcp_edge_audit_exporter_audit(&ex), -EBADMSG);
}

ZTEST(edge_security, test_audit_exporter_reports_overwritten_journal_gap)
{
	struct pqcp_edge_export_cursor *c = NULL;
	struct pqcp_edge_export_batch b;
	int ret;

	journal_setup();
	exporter_setup();
	for (uint32_t i = 1U; i <= 5U; ++i) {
		jappend(i);
	}
	/* The oldest records were overwritten by the 3-entry ring. */
	zassert_equal(pqcp_edge_audit_export_open(&ex, "uplink", 1U, T0,
		100000U, &c), 0);
	ret = pqcp_edge_audit_export_batch(&ex, &journal, c->cursor_id, 10U,
		T0 + 10U, &b);
	zassert_equal(ret, -EOVERFLOW);
	zassert_equal(b.first_sequence, 1U);
	zassert_equal(b.last_sequence, 2U);
	zassert_equal(b.record_count, 0U);
	zassert_equal(c->next_sequence, 1U);
	/* Explicitly acknowledging the gap lets the consumer resume. */
	zassert_equal(pqcp_edge_audit_export_acknowledge(&ex, c->cursor_id,
		b.last_sequence), 0);
	zassert_equal(pqcp_edge_audit_export_batch(&ex, &journal,
		c->cursor_id, 10U, T0 + 11U, &b), 0);
	zassert_equal(b.first_sequence, 3U);
	zassert_equal(b.last_sequence, 5U);
	zassert_equal(b.record_count, 3U);
	/* Caught up is still plain -EAGAIN. */
	zassert_equal(pqcp_edge_audit_export_acknowledge(&ex, c->cursor_id,
		5U), 0);
	zassert_equal(pqcp_edge_audit_export_batch(&ex, &journal,
		c->cursor_id, 10U, T0 + 12U, &b), -EAGAIN);
}
