###########################################################
#
# lib/jobs.py - Vigiles background job helpers.
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
#
###########################################################

import time

from . import llapi

JOB_POLL_INTERVAL = 1
JOB_TERMINAL_STATUSES = {"succeeded", "failed"}
DEFAULT_JOB_TIMEOUT = 600


def wait_for_job(email, key, job_id, timeout=DEFAULT_JOB_TIMEOUT):
    """Poll a Vigiles background job until it succeeds, fails, or times out."""
    if not job_id:
        raise Exception('Vigiles server did not return a job_id')

    resource = '/api/v1/vigiles/jobs/%s' % job_id
    deadline = time.monotonic() + timeout

    while True:
        result = llapi.api_get(email, key, resource)
        status = result.get('status') if result else None

        if status in JOB_TERMINAL_STATUSES:
            if status == 'failed':
                error = result.get('error') or 'Background job failed'
                raise Exception('Vigiles job %s failed: %s' % (job_id, error))
            return result

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Exception('Timed out waiting for Vigiles job %s after %s seconds' %
                            (job_id, timeout))
        time.sleep(min(JOB_POLL_INTERVAL, remaining))