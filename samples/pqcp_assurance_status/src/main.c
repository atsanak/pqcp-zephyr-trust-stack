/*
 * SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
 *
 * Build-only assurance status sample.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include "pqcp_assurance_digest_generated.h"

int main(void)
{
    printk("PQCP_ASSURANCE_STATUS schema=%d algorithm=%s artifacts=%d digest=%s\n",
           PQCP_ASSURANCE_DIGEST_SCHEMA_VERSION,
           PQCP_ASSURANCE_DIGEST_ALGORITHM,
           PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT,
           PQCP_ASSURANCE_DIGEST_ROOT_SHA256);
    printk("PQCP_ASSURANCE_STATUS source=%s generated_at=%s\n",
           PQCP_ASSURANCE_DIGEST_SOURCE,
           PQCP_ASSURANCE_DIGEST_GENERATED_AT);
    printk("PROJECT EXECUTION SUCCESSFUL\n");
    return 0;
}
