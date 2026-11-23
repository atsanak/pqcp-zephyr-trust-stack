/*
 * SPDX-License-Identifier: MIT
 *
 * pqcp-evidence-register - append-only RFC 9162 log of verifier appraisal
 * statements with ML-DSA-65 signed checkpoints.
 *
 *   keygen            derive a log keypair from a 32-byte seed file
 *   register          append one statement to the on-disk log
 *   checkpoint        sign a checkpoint over the log (optionally at a prefix)
 *   receipt           emit an inclusion receipt against a signed checkpoint
 *   prove-consistency emit a consistency file between two checkpoints
 *   sign-file         sign a file's bytes (kit provenance, own ML-DSA context)
 *   verify-file       verify such a signature against a public key
 *
 * Everything is deterministic and seed-file driven: this tool never reads
 * randomness (the linked randombytes stub aborts if anything tries).
 * Formats: docs/transparent-appraisal-format.md.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <pqcp_zephyr/fleet_transparency.h>

#include "host_sha256.h"
#include "kit_sign.h"
#include "receipt_codec.h"
#include "receipt_mldsa_ops.h"

#define MAX_FILE_BYTES (16U * 1024U * 1024U)
#define MAX_STATEMENT_ENTRY RC_MAX_STATEMENT_BYTES

static void die(const char *fmt, const char *detail)
	__attribute__((noreturn));

static void die(const char *fmt, const char *detail)
{
	fprintf(stderr, "PQCP_REGISTER ERROR ");
	fprintf(stderr, fmt, detail != NULL ? detail : "");
	fprintf(stderr, "\n");
	exit(1);
}

/* ------------------------------------------------------------------ */
/* File helpers                                                         */
/* ------------------------------------------------------------------ */

static bool path_join(char *out, size_t cap, const char *dir,
		      const char *name)
{
	int n = snprintf(out, cap, "%s/%s", dir, name);

	return n > 0 && (size_t)n < cap;
}

/* Returns 0, -ENOENT when the file does not exist, or another -errno. */
static int read_file(const char *path, uint8_t **data, size_t *length)
{
	FILE *f = fopen(path, "rb");
	long size;
	uint8_t *buf;

	if (f == NULL) {
		return errno == ENOENT ? -ENOENT : -EIO;
	}
	if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0 ||
	    (unsigned long)size > MAX_FILE_BYTES ||
	    fseek(f, 0, SEEK_SET) != 0) {
		(void)fclose(f);
		return -EIO;
	}
	buf = malloc((size_t)size + 1U);
	if (buf == NULL) {
		(void)fclose(f);
		return -ENOMEM;
	}
	if (fread(buf, 1U, (size_t)size, f) != (size_t)size) {
		free(buf);
		(void)fclose(f);
		return -EIO;
	}
	(void)fclose(f);
	*data = buf;
	*length = (size_t)size;
	return 0;
}

static int write_file(const char *path, const uint8_t *data, size_t length,
		      const char *mode)
{
	FILE *f = fopen(path, mode);

	if (f == NULL) {
		return -EIO;
	}
	if (length != 0U && fwrite(data, 1U, length, f) != length) {
		(void)fclose(f);
		return -EIO;
	}
	return fclose(f) == 0 ? 0 : -EIO;
}

static void hex_of(const uint8_t *in, size_t length, char *out)
{
	static const char hex[] = "0123456789abcdef";

	for (size_t i = 0U; i < length; ++i) {
		out[2U * i] = hex[in[i] >> 4];
		out[2U * i + 1U] = hex[in[i] & 0x0fU];
	}
	out[2U * length] = '\0';
}

/* ------------------------------------------------------------------ */
/* Option parsing                                                       */
/* ------------------------------------------------------------------ */

struct opts {
	int argc;
	char **argv; /* option area, starts after the sub-command */
};

/* Returns the value following `name`, or NULL when absent. Dies on a
 * trailing flag without a value.
 */
static const char *opt_get(const struct opts *o, const char *name)
{
	for (int i = 0; i < o->argc; ++i) {
		if (strcmp(o->argv[i], name) == 0) {
			if (i + 1 >= o->argc) {
				die("option %s needs a value", name);
			}
			return o->argv[i + 1];
		}
	}
	return NULL;
}

static bool opt_flag(const struct opts *o, const char *name)
{
	for (int i = 0; i < o->argc; ++i) {
		if (strcmp(o->argv[i], name) == 0) {
			return true;
		}
	}
	return false;
}

static const char *opt_require(const struct opts *o, const char *name)
{
	const char *value = opt_get(o, name);

	if (value == NULL) {
		die("missing required option %s", name);
	}
	return value;
}

/* Reject any token that is not a known option, its value, or a known flag. */
static void opts_check(const struct opts *o, const char *const *valued,
		       const char *const *flags)
{
	for (int i = 0; i < o->argc; ++i) {
		bool known = false;

		for (size_t k = 0U; valued[k] != NULL; ++k) {
			if (strcmp(o->argv[i], valued[k]) == 0) {
				known = true;
				++i;
				break;
			}
		}
		for (size_t k = 0U; !known && flags[k] != NULL; ++k) {
			known = strcmp(o->argv[i], flags[k]) == 0;
		}
		if (!known) {
			die("unknown option %s", o->argv[i]);
		}
	}
}

static uint64_t parse_u64(const char *name, const char *text)
{
	char *end = NULL;
	unsigned long long value;

	errno = 0;
	value = strtoull(text, &end, 10);
	if (text[0] == '\0' || text[0] == '-' || *end != '\0' || errno != 0) {
		die("option %s needs an unsigned integer", name);
	}
	return (uint64_t)value;
}

/* ------------------------------------------------------------------ */
/* On-disk log                                                          */
/* ------------------------------------------------------------------ */

struct log_state {
	struct pqcp_fleet_transparency_log log;
	struct pqcp_fleet_transparency_workspace ws;
	struct pqcp_fleet_transparency_hash_ops hash;
	uint8_t (*leaves)[PQCP_FLEET_TRANSPARENCY_DIGEST_BYTES];
	size_t count;
	uint8_t *stmt_data;
	size_t stmt_length;
	/* Offsets into stmt_data of each statement body, and its length. */
	size_t *stmt_offset;
	uint32_t *stmt_len;
};

static uint32_t be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Load and audit a log directory. A missing directory or missing files are
 * an empty log. extra reserves room for appends. Dies on any integrity
 * failure: count mismatch, leaf != H(0x00||statement), restore/verify error.
 */
static struct log_state *load_log(const char *dir,
				  const uint8_t log_id[32], size_t extra)
{
	struct log_state *st = calloc(1U, sizeof(*st));
	char leaves_path[1024];
	char stmts_path[1024];
	uint8_t *leaf_bytes = NULL;
	size_t leaf_len = 0U;
	int ret;

	if (st == NULL) {
		die("out of memory%s", "");
	}
	host_sha256_hash_ops(&st->hash);
	if (!path_join(leaves_path, sizeof(leaves_path), dir, "log.leaves") ||
	    !path_join(stmts_path, sizeof(stmts_path), dir, "log.statements")) {
		die("log dir path too long%s", "");
	}
	ret = read_file(leaves_path, &leaf_bytes, &leaf_len);
	if (ret == -ENOENT) {
		leaf_len = 0U;
	} else if (ret != 0) {
		die("cannot read %s", leaves_path);
	}
	if (leaf_len % 32U != 0U) {
		die("log.leaves length is not a multiple of 32%s", "");
	}
	st->count = leaf_len / 32U;
	st->leaves = calloc(st->count + extra + 1U, 32U);
	st->stmt_offset = calloc(st->count + 1U, sizeof(size_t));
	st->stmt_len = calloc(st->count + 1U, sizeof(uint32_t));
	if (st->leaves == NULL || st->stmt_offset == NULL ||
	    st->stmt_len == NULL) {
		die("out of memory%s", "");
	}
	if (leaf_len != 0U) {
		memcpy(st->leaves, leaf_bytes, leaf_len);
	}
	free(leaf_bytes);

	ret = read_file(stmts_path, &st->stmt_data, &st->stmt_length);
	if (ret == -ENOENT) {
		st->stmt_data = NULL;
		st->stmt_length = 0U;
	} else if (ret != 0) {
		die("cannot read %s", stmts_path);
	}
	{
		size_t off = 0U;
		size_t seen = 0U;

		while (off < st->stmt_length) {
			uint32_t n;

			if (st->stmt_length - off < 4U) {
				die("log.statements truncated%s", "");
			}
			n = be32(st->stmt_data + off);
			off += 4U;
			if (n > MAX_STATEMENT_ENTRY ||
			    n > st->stmt_length - off) {
				die("log.statements entry out of range%s", "");
			}
			if (seen >= st->count) {
				die("log.statements has more entries than log.leaves%s",
				    "");
			}
			st->stmt_offset[seen] = off;
			st->stmt_len[seen] = n;
			off += n;
			++seen;
		}
		if (seen != st->count) {
			die("log.statements has fewer entries than log.leaves%s",
			    "");
		}
	}
	for (size_t i = 0U; i < st->count; ++i) {
		uint8_t expect[32];

		if (pqcp_fleet_transparency_leaf_hash(
			    &st->hash, st->stmt_data + st->stmt_offset[i],
			    st->stmt_len[i], expect) != 0 ||
		    memcmp(expect, st->leaves[i], 32U) != 0) {
			char idx[24];

			(void)snprintf(idx, sizeof(idx), "%zu", i);
			die("leaf %s does not match its statement", idx);
		}
	}
	if (pqcp_fleet_transparency_log_init(&st->log, log_id, st->leaves,
					     st->count + extra + 1U,
					     &st->hash) != 0 ||
	    pqcp_fleet_transparency_log_restore(&st->log, st->count, 1U,
						&st->ws) != 0 ||
	    pqcp_fleet_transparency_log_verify(&st->log, &st->ws) != 0) {
		die("log restore/verify failed%s", "");
	}
	return st;
}

static void free_log(struct log_state *st)
{
	free(st->leaves);
	free(st->stmt_data);
	free(st->stmt_offset);
	free(st->stmt_len);
	free(st);
}

/* ------------------------------------------------------------------ */
/* Key helpers                                                          */
/* ------------------------------------------------------------------ */

static void read_seed(const char *path, uint8_t seed[32])
{
	uint8_t *data = NULL;
	size_t length = 0U;

	if (read_file(path, &data, &length) != 0) {
		die("cannot read seed file %s", path);
	}
	if (length != RECEIPT_MLDSA_SEED_BYTES) {
		free(data);
		die("seed file must be exactly 32 bytes%s", "");
	}
	memcpy(seed, data, 32U);
	free(data);
}

static void read_pk(const char *path, uint8_t pk[RECEIPT_MLDSA_PK_BYTES])
{
	uint8_t *data = NULL;
	size_t length = 0U;

	if (read_file(path, &data, &length) != 0) {
		die("cannot read public key %s", path);
	}
	if (length != RECEIPT_MLDSA_PK_BYTES) {
		free(data);
		die("public key must be exactly 1952 bytes%s", "");
	}
	memcpy(pk, data, length);
	free(data);
}

static void read_checkpoint(const char *path, struct rc_checkpoint *c)
{
	uint8_t *data = NULL;
	size_t length = 0U;

	if (read_file(path, &data, &length) != 0) {
		die("cannot read checkpoint %s", path);
	}
	if (rc_checkpoint_decode(data, length, c) != 0) {
		free(data);
		die("malformed checkpoint %s", path);
	}
	free(data);
}

/* ------------------------------------------------------------------ */
/* Commands                                                             */
/* ------------------------------------------------------------------ */

static int cmd_keygen(const struct opts *o)
{
	static const char *const valued[] = { "--seed-file", "--pk-out", NULL };
	static const char *const flags[] = { NULL };
	uint8_t seed[32];
	struct receipt_mldsa_ctx *ctx = calloc(1U, sizeof(*ctx));
	char hex[65];

	opts_check(o, valued, flags);
	if (ctx == NULL) {
		die("out of memory%s", "");
	}
	read_seed(opt_require(o, "--seed-file"), seed);
	if (receipt_mldsa_ctx_init_sign(ctx, seed) != 0) {
		die("keypair derivation failed%s", "");
	}
	if (write_file(opt_require(o, "--pk-out"), ctx->pk,
		       RECEIPT_MLDSA_PK_BYTES, "wb") != 0) {
		die("cannot write %s", opt_get(o, "--pk-out"));
	}
	hex_of(ctx->key_id, 32U, hex);
	printf("PQCP_REGISTER KEYGEN key_id=%s pk_bytes=%u\n", hex,
	       RECEIPT_MLDSA_PK_BYTES);
	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
	return 0;
}

static int cmd_register(const struct opts *o)
{
	static const char *const valued[] = {
		"--log-dir", "--log-pk", "--statement", NULL
	};
	static const char *const flags[] = { "--raw", NULL };
	const char *dir = opt_require(o, "--log-dir");
	uint8_t pk[RECEIPT_MLDSA_PK_BYTES];
	uint8_t log_id[32];
	uint8_t *statement = NULL;
	size_t statement_len = 0U;
	struct log_state *st;
	struct rc_statement *parsed;
	uint64_t index;
	uint8_t lenbuf[4];
	char leaves_path[1024];
	char stmts_path[1024];
	char root_hex[65];
	char leaf_hex[65];
	uint8_t leaf[32];

	opts_check(o, valued, flags);
	read_pk(opt_require(o, "--log-pk"), pk);
	receipt_mldsa_key_id(pk, log_id);
	if (read_file(opt_require(o, "--statement"), &statement,
		      &statement_len) != 0) {
		die("cannot read statement %s", opt_get(o, "--statement"));
	}
	if (statement_len > MAX_STATEMENT_ENTRY) {
		die("statement exceeds %s bytes", "512");
	}
	if (!opt_flag(o, "--raw")) {
		parsed = calloc(1U, sizeof(*parsed));
		if (parsed == NULL ||
		    rc_statement_decode(statement, statement_len, parsed) !=
			    0) {
			die("statement is not a valid appraisal statement%s",
			    "");
		}
		free(parsed);
	}
	if (mkdir(dir, 0777) != 0 && errno != EEXIST) {
		die("cannot create log dir %s", dir);
	}
	st = load_log(dir, log_id, 1U);
	if (pqcp_fleet_transparency_log_append(&st->log, statement,
					       statement_len, &st->ws,
					       &index) != 0) {
		die("append failed%s", "");
	}
	if (pqcp_fleet_transparency_leaf_hash(&st->hash, statement,
					      statement_len, leaf) != 0) {
		die("hash failed%s", "");
	}
	if (!path_join(leaves_path, sizeof(leaves_path), dir, "log.leaves") ||
	    !path_join(stmts_path, sizeof(stmts_path), dir, "log.statements")) {
		die("log dir path too long%s", "");
	}
	lenbuf[0] = (uint8_t)(statement_len >> 24);
	lenbuf[1] = (uint8_t)(statement_len >> 16);
	lenbuf[2] = (uint8_t)(statement_len >> 8);
	lenbuf[3] = (uint8_t)statement_len;
	if (write_file(stmts_path, lenbuf, 4U, "ab") != 0 ||
	    write_file(stmts_path, statement, statement_len, "ab") != 0 ||
	    write_file(leaves_path, leaf, 32U, "ab") != 0) {
		die("cannot append to log files in %s", dir);
	}
	hex_of(st->log.root, 32U, root_hex);
	hex_of(leaf, 32U, leaf_hex);
	printf("PQCP_REGISTER APPEND leaf_index=%llu tree_size=%llu root=%s leaf_hash=%s\n",
	       (unsigned long long)index,
	       (unsigned long long)st->log.tree_size, root_hex, leaf_hex);
	free(statement);
	free_log(st);
	return 0;
}

static int cmd_checkpoint(const struct opts *o)
{
	static const char *const valued[] = {
		"--log-dir", "--seed-file", "--sequence", "--timestamp-ms",
		"--tree-size", "--out", NULL
	};
	static const char *const flags[] = { NULL };
	uint8_t seed[32];
	struct receipt_mldsa_ctx *kctx = calloc(1U, sizeof(*kctx));
	struct pqcp_fleet_transparency_signature_ops sigops;
	struct pqcp_fleet_transparency_snapshot snap;
	struct pqcp_fleet_transparency_checkpoint fleet;
	struct rc_checkpoint *rc = calloc(1U, sizeof(*rc));
	uint8_t sig[RC_SIGNATURE_BYTES];
	uint8_t out[RC_MAX_CHECKPOINT_BYTES];
	size_t out_len = 0U;
	struct log_state *st;
	uint64_t sequence;
	uint64_t timestamp = 0U;
	uint64_t tree_size;
	const char *text;
	char root_hex[65];
	char id_hex[65];

	opts_check(o, valued, flags);
	if (kctx == NULL || rc == NULL) {
		die("out of memory%s", "");
	}
	read_seed(opt_require(o, "--seed-file"), seed);
	if (receipt_mldsa_ctx_init_sign(kctx, seed) != 0) {
		die("keypair derivation failed%s", "");
	}
	sequence = parse_u64("--sequence", opt_require(o, "--sequence"));
	if (sequence == 0U) {
		die("--sequence must be non-zero%s", "");
	}
	if ((text = opt_get(o, "--timestamp-ms")) != NULL) {
		timestamp = parse_u64("--timestamp-ms", text);
	}
	st = load_log(opt_require(o, "--log-dir"), kctx->key_id, 0U);
	tree_size = st->count;
	if ((text = opt_get(o, "--tree-size")) != NULL) {
		tree_size = parse_u64("--tree-size", text);
		if (tree_size > st->count) {
			die("--tree-size exceeds log size%s", "");
		}
	}
	memset(&snap, 0, sizeof(snap));
	snap.schema_version = PQCP_FLEET_TRANSPARENCY_SCHEMA_VERSION;
	snap.tree_size = tree_size;
	snap.generation = st->log.generation;
	memcpy(snap.log_id, kctx->key_id, 32U);
	if (tree_size == st->count) {
		memcpy(snap.root, st->log.root, 32U);
	} else if (pqcp_fleet_transparency_root_from_hashes(
			   &st->hash, st->leaves, (size_t)tree_size,
			   snap.root) != 0) {
		die("cannot compute prefix root%s", "");
	}
	receipt_mldsa_signature_ops(&sigops, kctx);
	if (pqcp_fleet_transparency_checkpoint_sign(
		    &snap, timestamp, sequence, kctx->key_id, &st->hash,
		    &sigops, sig, sizeof(sig), &fleet) != 0) {
		die("checkpoint signing failed%s", "");
	}
	if (rc_checkpoint_from_fleet(&fleet, rc) != 0 ||
	    rc_checkpoint_encode(rc, out, sizeof(out), &out_len) != 0 ||
	    write_file(opt_require(o, "--out"), out, out_len, "wb") != 0) {
		die("cannot write checkpoint %s", opt_get(o, "--out"));
	}
	hex_of(rc->root, 32U, root_hex);
	hex_of(rc->log_id, 32U, id_hex);
	printf("PQCP_REGISTER CHECKPOINT tree_size=%llu sequence=%llu root=%s log_id=%s\n",
	       (unsigned long long)rc->tree_size,
	       (unsigned long long)rc->sequence, root_hex, id_hex);
	memset(kctx, 0, sizeof(*kctx));
	free(kctx);
	free(rc);
	free_log(st);
	return 0;
}

static int cmd_receipt(const struct opts *o)
{
	static const char *const valued[] = {
		"--log-dir", "--checkpoint", "--leaf-index", "--out", NULL
	};
	static const char *const flags[] = { "--allow-mismatch", NULL };
	struct rc_receipt *rc = calloc(1U, sizeof(*rc));
	struct pqcp_fleet_transparency_inclusion_proof *proof =
		calloc(1U, sizeof(*proof));
	uint8_t *out = malloc(RC_MAX_RECEIPT_BYTES);
	size_t out_len = 0U;
	struct log_state *st;
	uint64_t index;

	opts_check(o, valued, flags);
	if (rc == NULL || proof == NULL || out == NULL) {
		die("out of memory%s", "");
	}
	read_checkpoint(opt_require(o, "--checkpoint"), &rc->checkpoint);
	index = parse_u64("--leaf-index", opt_require(o, "--leaf-index"));
	st = load_log(opt_require(o, "--log-dir"), rc->checkpoint.log_id, 0U);
	if (rc->checkpoint.tree_size > st->count || index >= st->count ||
	    index >= rc->checkpoint.tree_size) {
		die("leaf index or checkpoint size outside the log%s", "");
	}
	if (pqcp_fleet_transparency_inclusion_proof_generate(
		    &st->log, index, rc->checkpoint.tree_size, proof) != 0) {
		die("inclusion proof generation failed%s", "");
	}
	if (memcmp(proof->root, rc->checkpoint.root, 32U) != 0 &&
	    !opt_flag(o, "--allow-mismatch")) {
		die("checkpoint root does not match this log (use --allow-mismatch for fixtures)%s",
		    "");
	}
	rc->statement_length = st->stmt_len[index];
	memcpy(rc->statement, st->stmt_data + st->stmt_offset[index],
	       rc->statement_length);
	rc->leaf_index = index;
	rc->tree_size = rc->checkpoint.tree_size;
	rc->path_count = proof->node_count;
	memcpy(rc->path, proof->nodes, proof->node_count * 32U);
	if (rc_receipt_encode(rc, out, RC_MAX_RECEIPT_BYTES, &out_len) != 0 ||
	    write_file(opt_require(o, "--out"), out, out_len, "wb") != 0) {
		die("cannot write receipt %s", opt_get(o, "--out"));
	}
	printf("PQCP_REGISTER RECEIPT leaf_index=%llu tree_size=%llu path_nodes=%zu\n",
	       (unsigned long long)rc->leaf_index,
	       (unsigned long long)rc->tree_size, rc->path_count);
	free(out);
	free(proof);
	free(rc);
	free_log(st);
	return 0;
}

static int cmd_prove_consistency(const struct opts *o)
{
	static const char *const valued[] = {
		"--log-dir", "--old-checkpoint", "--new-checkpoint", "--out",
		NULL
	};
	static const char *const flags[] = { "--allow-mismatch", NULL };
	struct rc_consistency *rc = calloc(1U, sizeof(*rc));
	struct pqcp_fleet_transparency_consistency_proof *proof =
		calloc(1U, sizeof(*proof));
	uint8_t *out = malloc(RC_MAX_CONSISTENCY_BYTES);
	size_t out_len = 0U;
	struct log_state *st;

	opts_check(o, valued, flags);
	if (rc == NULL || proof == NULL || out == NULL) {
		die("out of memory%s", "");
	}
	read_checkpoint(opt_require(o, "--old-checkpoint"),
			&rc->old_checkpoint);
	read_checkpoint(opt_require(o, "--new-checkpoint"),
			&rc->new_checkpoint);
	st = load_log(opt_require(o, "--log-dir"), rc->new_checkpoint.log_id,
		      0U);
	if (rc->old_checkpoint.tree_size > rc->new_checkpoint.tree_size ||
	    rc->new_checkpoint.tree_size > st->count) {
		die("checkpoint sizes are not a valid growth inside the log%s",
		    "");
	}
	if (pqcp_fleet_transparency_consistency_proof_generate(
		    &st->log, rc->old_checkpoint.tree_size,
		    rc->new_checkpoint.tree_size, proof) != 0) {
		die("consistency proof generation failed%s", "");
	}
	if ((memcmp(proof->old_root, rc->old_checkpoint.root, 32U) != 0 ||
	     memcmp(proof->new_root, rc->new_checkpoint.root, 32U) != 0) &&
	    !opt_flag(o, "--allow-mismatch")) {
		die("checkpoint roots do not match this log (use --allow-mismatch for fixtures)%s",
		    "");
	}
	rc->old_size = rc->old_checkpoint.tree_size;
	rc->new_size = rc->new_checkpoint.tree_size;
	rc->node_count = proof->node_count;
	memcpy(rc->nodes, proof->nodes, proof->node_count * 32U);
	if (rc_consistency_encode(rc, out, RC_MAX_CONSISTENCY_BYTES,
				  &out_len) != 0 ||
	    write_file(opt_require(o, "--out"), out, out_len, "wb") != 0) {
		die("cannot write consistency file %s", opt_get(o, "--out"));
	}
	printf("PQCP_REGISTER CONSISTENCY old_size=%llu new_size=%llu nodes=%zu\n",
	       (unsigned long long)rc->old_size,
	       (unsigned long long)rc->new_size, rc->node_count);
	free(out);
	free(proof);
	free(rc);
	free_log(st);
	return 0;
}

/* The kit-provenance context is the default. The log context is reachable
 * only through this explicit fixture flag so tests can prove a checkpoint-
 * context signature is refused by the default verify-file.
 */
static const char *file_context(const struct opts *o)
{
	return opt_flag(o, "--fixture-log-context") ? RECEIPT_MLDSA_CONTEXT :
						      KIT_SIGN_CONTEXT_KIT;
}

static int cmd_sign_file(const struct opts *o)
{
	static const char *const valued[] = {
		"--seed-file", "--in", "--out", NULL
	};
	static const char *const flags[] = { "--fixture-log-context", NULL };
	uint8_t seed[32];
	struct receipt_mldsa_ctx *kctx = calloc(1U, sizeof(*kctx));
	uint8_t sig[RECEIPT_MLDSA_SIG_BYTES];
	uint8_t *data = NULL;
	size_t length = 0U;
	char hex[65];

	opts_check(o, valued, flags);
	if (kctx == NULL) {
		die("out of memory%s", "");
	}
	read_seed(opt_require(o, "--seed-file"), seed);
	if (receipt_mldsa_ctx_init_sign(kctx, seed) != 0) {
		die("keypair derivation failed%s", "");
	}
	if (read_file(opt_require(o, "--in"), &data, &length) != 0) {
		die("cannot read input %s", opt_get(o, "--in"));
	}
	if (kit_sign_message(kctx, file_context(o), data, length, sig) != 0) {
		die("signing failed%s", "");
	}
	if (write_file(opt_require(o, "--out"), sig, sizeof(sig), "wb") != 0) {
		die("cannot write %s", opt_get(o, "--out"));
	}
	hex_of(kctx->key_id, 32U, hex);
	printf("PQCP_REGISTER SIGN-FILE key_id=%s bytes=%zu sig_bytes=%u\n",
	       hex, length, RECEIPT_MLDSA_SIG_BYTES);
	memset(kctx, 0, sizeof(*kctx));
	free(kctx);
	free(data);
	return 0;
}

static int cmd_verify_file(const struct opts *o)
{
	static const char *const valued[] = { "--pk", "--in", "--sig", NULL };
	static const char *const flags[] = { "--fixture-log-context", NULL };
	uint8_t pk[RECEIPT_MLDSA_PK_BYTES];
	uint8_t key_id[32];
	uint8_t *data = NULL;
	uint8_t *sig = NULL;
	size_t length = 0U;
	size_t sig_len = 0U;
	char hex[65];

	opts_check(o, valued, flags);
	read_pk(opt_require(o, "--pk"), pk);
	receipt_mldsa_key_id(pk, key_id);
	hex_of(key_id, 32U, hex);
	if (read_file(opt_require(o, "--in"), &data, &length) != 0) {
		die("cannot read input %s", opt_get(o, "--in"));
	}
	if (read_file(opt_require(o, "--sig"), &sig, &sig_len) != 0) {
		die("cannot read signature %s", opt_get(o, "--sig"));
	}
	if (sig_len != RECEIPT_MLDSA_SIG_BYTES) {
		printf("PQCP_REGISTER VERIFY-FILE REJECT reason=sig_malformed key_id=%s\n",
		       hex);
		free(data);
		free(sig);
		return 1;
	}
	if (kit_verify_message(pk, file_context(o), data, length, sig,
			       sig_len) != 0) {
		printf("PQCP_REGISTER VERIFY-FILE REJECT reason=bad_signature key_id=%s\n",
		       hex);
		free(data);
		free(sig);
		return 1;
	}
	printf("PQCP_REGISTER VERIFY-FILE PASS key_id=%s bytes=%zu\n", hex,
	       length);
	free(data);
	free(sig);
	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s <command> [options]\n"
		"  keygen --seed-file S --pk-out P\n"
		"  register --log-dir D --log-pk P --statement STMT.cbor [--raw]\n"
		"  checkpoint --log-dir D --seed-file S --sequence N [--timestamp-ms T]\n"
		"             [--tree-size K] --out CKPT.cbor\n"
		"  receipt --log-dir D --checkpoint CKPT.cbor --leaf-index I --out R.cbor\n"
		"          [--allow-mismatch]\n"
		"  prove-consistency --log-dir D --old-checkpoint O --new-checkpoint N\n"
		"          --out C.cbor [--allow-mismatch]\n"
		"  sign-file --seed-file S --in F --out SIG\n"
		"  verify-file --pk P --in F --sig SIG\n"
		"          (ML-DSA-65, context PQCP-KIT-PROVENANCE-V1, deterministic)\n"
		"Seed files are 32 raw bytes; no command reads randomness.\n"
		"Exit 0 ok, 1 operation or option error, 2 usage (no/unknown command).\n",
		argv0);
}

int main(int argc, char **argv)
{
	struct opts o;

	if (argc < 2) {
		usage(argv[0]);
		return 2;
	}
	o.argc = argc - 2;
	o.argv = argv + 2;
	if (strcmp(argv[1], "keygen") == 0) {
		return cmd_keygen(&o);
	}
	if (strcmp(argv[1], "register") == 0) {
		return cmd_register(&o);
	}
	if (strcmp(argv[1], "checkpoint") == 0) {
		return cmd_checkpoint(&o);
	}
	if (strcmp(argv[1], "receipt") == 0) {
		return cmd_receipt(&o);
	}
	if (strcmp(argv[1], "prove-consistency") == 0) {
		return cmd_prove_consistency(&o);
	}
	if (strcmp(argv[1], "sign-file") == 0) {
		return cmd_sign_file(&o);
	}
	if (strcmp(argv[1], "verify-file") == 0) {
		return cmd_verify_file(&o);
	}
	usage(argv[0]);
	return 2;
}
