# PANDI ccTLD Sovereign DNS Health and Threat Radar

Interactive analytical dashboard for PeDaS 2026 Finals (Pesta Data Nasional) - Business Analytics on DNS ccTLD .id telemetry.

- **Team**: Tolong Jangan Ditimpa Ya Mas (Finalist #14)
- **Competition**: Pesta Data Nasional (PeDaS) 2026 - Babak Final
- **Host**: PANDI (Pengelola Nama Domain Internet Indonesia)
- **Review Standard**: Double-Blind Review

## Live Dashboard

https://pedas2026-pandi-radar-1.streamlit.app

## Architecture and Components

1. **Dashboard UI**: Streamlit 1.42 with Plotly Express and Graph Objects.
2. **Data Engine**: High-performance pre-aggregated Apache Parquet matrices (~177 KB total footprint).
3. **Telemetry Analysis**:
   - Temporal query vs response message volume (11.7M messages / 30 minutes).
   - Protocol rigor: QTYPE over queries (N = 5.86M), RCODE over responses (N = 5.85M).
   - Resolver centralization and DNSSEC validation asymmetry.
   - IDADX threat lexicon cross-correlation (.go.id and .ac.id subdomain weaponization).
   - Algorithmic DGA candidate entropy detection and IP MTU response fragmentation.

## Local Execution

```bash
pip install -r requirements.txt
streamlit run app.py
```
