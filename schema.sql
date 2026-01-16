DROP TABLE IF EXISTS cves;

CREATE TABLE cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    published_date TEXT,
    severity TEXT,
    cvss_score REAL,
    vendor TEXT,
    product TEXT
);
