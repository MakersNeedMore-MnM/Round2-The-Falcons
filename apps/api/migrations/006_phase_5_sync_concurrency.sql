CREATE UNIQUE INDEX taxii_sync_jobs_one_running_per_source_idx
ON taxii_sync_jobs (source_id)
WHERE status = 'running';
