```markdown
# 🛡️ Trust Chain Expiry Radar

An autonomous data plane running entirely on GitHub Actions that maintains a multi-dimensional directed graph of X.509 certificate paths across different client trust stores (Mozilla NSS, Android Legacy, Chromium Root Store). It resolves cross-signing entanglements and produces deterministic path proofs and expiration warnings for AI agents.

## Token Impact
- **Context Reduction**: 93% – 99%
- **Input Overhead**: Shrinks 25,000+ tokens of raw certificates, openssl logs, and root lists to a ~300 token path witness proof.

## Shared Wire Endpoints
- [`/v1/manifest.json`](public/v1/manifest.json)
- [`/today.json`](public/today.json)
- [`/v1/schema.json`](public/v1/schema.json)
- [`/v1/radar/30d.json`](public/v1/radar/30d.json)
- [`/v1/radar/90d.json`](public/v1/radar/90d.json)
- [`/certificate-graph.parquet`](public/certificate-graph.parquet) (Columnar DuckDB snapshot)
- [`/llms.txt`](public/llms.txt)

## Architecture
- **Graph Resolver**: Directed path enumeration across versioned store profiles in Python & DuckDB
- **Profiles**: `mozilla-current`, `android-legacy`, `chromium-current`
- **Proof Mechanism**: SHA-256 hashed path witness records
- **Storage**: DuckDB + Parquet
- **Ledger**: Append-only Git-committed JSONL in `/ledger`
- **Edge Delivery**: GitHub Pages (Fastly CDN)
