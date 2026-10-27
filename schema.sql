CREATE SEQUENCE IF NOT EXISTS seq_commit_id START 1;

CREATE TABLE IF NOT EXISTS trust_anchors (
    anchor_id VARCHAR PRIMARY KEY,
    profile VARCHAR,
    subject_dn VARCHAR,
    spki_sha256 VARCHAR,
    key_algorithm VARCHAR,
    not_before_utc VARCHAR,
    not_after_utc VARCHAR,
    days_to_expiry INTEGER,
    content_hash VARCHAR,
    indexed_at_utc VARCHAR
);

CREATE TABLE IF NOT EXISTS certificate_paths (
    leaf_spki_sha256 VARCHAR,
    profile VARCHAR,
    subject_cn VARCHAR,
    issuer_cn VARCHAR,
    path_status VARCHAR,
    earliest_failure_utc VARCHAR,
    days_until_failure INTEGER,
    failure_cause VARCHAR,
    alternative_paths_count INTEGER,
    witness_path_json VARCHAR,
    proof_hash VARCHAR,
    last_evaluated_utc VARCHAR,
    PRIMARY KEY (leaf_spki_sha256, profile)
);

CREATE TABLE IF NOT EXISTS radar_ledger (
    commit_id BIGINT PRIMARY KEY,
    timestamp_utc VARCHAR,
    operation VARCHAR,
    leaf_spki_sha256 VARCHAR,
    profile VARCHAR,
    status VARCHAR,
    days_until_failure INTEGER,
    proof_hash VARCHAR
);
