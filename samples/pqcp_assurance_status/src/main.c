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
    printk("PQCP_ASSURANCE_STATUS version=%s digest=%s artifact_count=%d schema=%d\n",
           PQCP_ASSURANCE_DIGEST_VERSION,
           PQCP_ASSURANCE_DIGEST_ROOT_SHA256,
           PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT,
           PQCP_ASSURANCE_DIGEST_SCHEMA_VERSION);
    for (int i = 0; i < PQCP_ASSURANCE_DIGEST_ARTIFACT_COUNT; ++i) {
        printk("PQCP_ASSURANCE_ARTIFACT name=%s sha256=%s\n",
               pqcp_assurance_digest_artifact_names[i],
               pqcp_assurance_digest_artifact_sha256[i]);
    }
    printk("PROJECT EXECUTION SUCCESSFUL\n");
    return 0;
}
