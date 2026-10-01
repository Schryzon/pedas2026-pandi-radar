"""
PANDI ccTLD Sovereign DNS Health & Threat Radar
Team: Tolong Jangan Ditimpa Ya Mas (Finalist #14)
PeDaS 2026 Finals - Interactive Business Analytics Dashboard
"""

import streamlit as st
import pandas as pd
import numpy as np
import json
from pathlib import Path
import plotly.express as px
import plotly.graph_objects as go

# Set page configuration
st.set_page_config(
    page_title="PANDI Sovereign DNS Health Radar | Team: Tolong Jangan Ditimpa Ya Mas",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Dark Slate & Sovereign Blue)
st.markdown("""
<style>
    .reportview-container {
        background-color: #0F172A;
    }
    .metric-card {
        background: linear-gradient(135deg, #1E293B, #0F172A);
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 12px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    .metric-title {
        color: #94A3B8;
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-value {
        color: #F8FAFC;
        font-size: 1.8rem;
        font-weight: 700;
        margin-top: 4px;
    }
    .metric-sub {
        color: #38BDF8;
        font-size: 0.8rem;
        margin-top: 2px;
    }
    .threat-tag {
        background-color: #EF4444;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Data Loader with Caching
@st.cache_data
def load_analytics_data():
    candidates = [
        Path("data"),
        Path(__file__).resolve().parent / "data",
        Path("finals/results"),
        Path("results"),
        Path(__file__).resolve().parent.parent.parent / "results",
        Path(__file__).resolve().parent.parent / "results",
        Path(__file__).resolve().parent / "results"
    ]
    base_dir = None
    for cand in candidates:
        if (cand / "dns_kpi_metrics.json").exists():
            base_dir = cand
            break
            
    if base_dir is None:
        raise FileNotFoundError(f"Could not find dns_kpi_metrics.json in any candidate path: {candidates}")
        
    with open(base_dir / "dns_kpi_metrics.json", "r") as f:
        kpi = json.load(f)
    
    temporal_df = pd.read_parquet(base_dir / "dns_temporal_summary.parquet")
    qtype_df = pd.read_parquet(base_dir / "dns_qtype_summary.parquet")
    rcode_df = pd.read_parquet(base_dir / "dns_rcode_summary.parquet")
    resolvers_df = pd.read_parquet(base_dir / "dns_top_resolvers.parquet")
    threat_df = pd.read_parquet(base_dir / "dns_threat_matches.parquet")
    sectors_df = pd.read_parquet(base_dir / "dns_compromised_sectors.parquet")
    sizes_df = pd.read_parquet(base_dir / "dns_response_sizes.parquet")
    dga_df = pd.read_parquet(base_dir / "dns_dga_candidates.parquet")
    
    return kpi, temporal_df, qtype_df, rcode_df, resolvers_df, threat_df, sectors_df, sizes_df, dga_df

try:
    kpi, temporal_df, qtype_df, rcode_df, resolvers_df, threat_df, sectors_df, sizes_df, dga_df = load_analytics_data()
except Exception as e:
    st.error(f"Error loading analytical data: {e}")
    st.stop()

# Header Section
st.title("PANDI ccTLD Sovereign DNS Health & Threat Radar")
st.caption("PeDaS 2026 Finals | Team: Tolong Jangan Ditimpa Ya Mas (Finalist #14) | Double-Blind Review Standard")

# KPI Summary Row
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Inbound Queries (qr=0)</div>
        <div class="metric-value">{kpi['total_queries']:,}</div>
        <div class="metric-sub">Mean: {kpi['queries_per_second']:.1f} QPS</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Outbound Responses (qr=1)</div>
        <div class="metric-value">{kpi['total_responses']:,}</div>
        <div class="metric-sub">Balance Ratio: 99.82%</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">IPv6 Modernization</div>
        <div class="metric-value">{kpi['ipv6_ratio_pct']:.2f}%</div>
        <div class="metric-sub">UDP: 69.77% | TCP: 2.65%</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">NXDOMAIN Failures</div>
        <div class="metric-value">{kpi['nxdomain_pct']:.2f}%</div>
        <div class="metric-sub">{kpi['nxdomain_count']:,} failed resolutions</div>
    </div>
    """, unsafe_allow_html=True)

with col5:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Compromised Domains</div>
        <div class="metric-value" style="color: #F87171;">{len(threat_df):,}</div>
        <div class="metric-sub">{kpi['gov_compromised_count']} Gov | {kpi['edu_compromised_count']} Edu subdomains</div>
    </div>
    """, unsafe_allow_html=True)

st.write("")

# Navigation Tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "1. Temporal Ingress & Protocols",
    "2. Protocol Matrix (QTYPE & RCODE)",
    "3. Resolver Centralization & DNSSEC",
    "4. IDADX Threat Hunter (.go.id / .ac.id)",
    "5. DGA & Infrastructure Resilience"
])

# TAB 1: TEMPORAL INGRESS & PROTOCOL DYNAMICS
with tab1:
    st.subheader("1. Temporal Traffic Dynamics & Protocol Mix")
    st.markdown("""
    Analysis of 11,712,623 DNS messages across 30 minutes shows near-perfect query/response equilibrium.
    **Key Finding:** ccTLD ingress is overwhelmingly **IPv6-dominated (72.42%)**, indicating rapid Indonesian telecom migration, but also highlighting new threat surfaces.
    """)
    
    col_t1, col_t2 = st.columns([7, 3])
    with col_t1:
        fig_time = go.Figure()
        fig_time.add_trace(go.Scatter(
            x=temporal_df['time_minute'], y=temporal_df['query_count'],
            mode='lines+markers', name='Queries (qr=0)', line=dict(color='#0284C7', width=2.5)
        ))
        fig_time.add_trace(go.Scatter(
            x=temporal_df['time_minute'], y=temporal_df['response_count'],
            mode='lines', name='Responses (qr=1)', line=dict(color='#10B981', width=2, dash='dash')
        ))
        fig_time.update_layout(
            title="Per-Minute Query vs Response Traffic Volume",
            xaxis_title="Timeline (WITA / UTC+8)",
            yaxis_title="Message Count / Minute",
            template="plotly_dark",
            margin=dict(l=40, r=40, t=50, b=40),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_time, use_container_width=True)
    
    with col_t2:
        proto_pie = pd.DataFrame({
            "Layer": ["IPv6 UDP", "IPv4 UDP", "IPv6 TCP", "IPv4 TCP"],
            "Packets": [8172268, 3029964, 310003, 200388]
        })
        fig_pie = px.pie(
            proto_pie, names="Layer", values="Packets",
            title="Network Protocol Composition",
            color_discrete_sequence=["#38BDF8", "#818CF8", "#34D399", "#F472B6"],
            template="plotly_dark"
        )
        fig_pie.update_traces(textposition='inside', textinfo='percent+label')
        fig_pie.update_layout(margin=dict(l=20, r=20, t=50, b=20), showlegend=False)
        st.plotly_chart(fig_pie, use_container_width=True)

# TAB 2: PROTOCOL MATRIX
with tab2:
    st.subheader("2. Protocol Rigor: Query Types & Response Code Denominators")
    st.markdown("""
    **Methodological Rigor Mandate:** To comply with official competition rules, QTYPE is strictly evaluated over queries (N = 5,861,701), while RCODE is strictly evaluated over responses (N = 5,850,922).
    """)
    
    col_p1, col_p2 = st.columns(2)
    with col_p1:
        fig_q = px.bar(
            qtype_df.head(8), x="qtype_name", y="query_percentage",
            text="query_percentage",
            title="Query Type Distribution (Denominator = 5.86M Queries)",
            labels={"qtype_name": "Query Type", "query_percentage": "Percentage (%)"},
            color="query_percentage",
            color_continuous_scale="Blues",
            template="plotly_dark"
        )
        fig_q.update_traces(texttemplate='%{text:.2f}%', textposition='outside')
        fig_q.update_layout(margin=dict(l=30, r=30, t=50, b=30), showlegend=False)
        st.plotly_chart(fig_q, use_container_width=True)
        st.caption("Note the high proportion of **NS queries (31.60%)**: Recursive resolvers continuously query PANDI for authoritative sub-zone delegations.")
    
    with col_p2:
        fig_r = px.bar(
            rcode_df.head(5), x="rcode_name", y="response_percentage",
            text="response_percentage",
            title="Response Code Distribution (Denominator = 5.85M Responses, Log Scale)",
            labels={"rcode_name": "Response Code", "response_percentage": "Percentage (%)"},
            color="rcode_name",
            color_discrete_map={"NOERROR": "#10B981", "NXDOMAIN": "#EF4444", "FORMERR": "#F59E0B", "NOTIMP": "#6B7280", "REFUSED": "#9CA3AF"},
            template="plotly_dark"
        )
        fig_r.update_yaxes(type="log")
        fig_r.update_traces(texttemplate='%{text:.3f}%', textposition='outside')
        fig_r.update_layout(margin=dict(l=30, r=30, t=50, b=30), showlegend=False)
        st.plotly_chart(fig_r, use_container_width=True)
        st.caption("NXDOMAIN constitutes **11.54% (675,229 responses)**. High NXDOMAIN volume is an empirical fingerprint of typosquatting, botnet DGA probing, and dangling delegations.")

# TAB 3: RESOLVER CENTRALIZATION & DNSSEC
with tab3:
    st.subheader("3. Infrastructure Resilience: Centralization Asymmetry & DNSSEC Posture")
    st.markdown("""
    **Vulnerability Alert:** A single recursive resolver subnet (`2d68:a529:78c2::/48`) accounts for **47.45% of all national ccTLD queries**.
    The top two AS-level `/32` allocations command **58.71% of total traffic**. This represents an acute single-point-of-failure risk.
    """)
    
    col_c1, col_c2 = st.columns([6, 4])
    with col_c1:
        top_res = resolvers_df.head(10).copy()
        top_res['display_subnet'] = top_res['client_subnet'].str.replace('::/48', '.../48')
        fig_res = px.bar(
            top_res, y="display_subnet", x="market_share_pct",
            orientation="h",
            text="market_share_pct",
            title="Top 10 Recursive Resolver Subnets Market Share (%)",
            labels={"display_subnet": "Resolver Subnet", "market_share_pct": "Query Share (%)"},
            color="market_share_pct",
            color_continuous_scale="Viridis",
            template="plotly_dark"
        )
        fig_res.update_traces(texttemplate='%{text:.2f}%', textposition='outside')
        fig_res.update_layout(yaxis=dict(autorange="reversed"), margin=dict(l=30, r=30, t=50, b=30), showlegend=False)
        st.plotly_chart(fig_res, use_container_width=True)
    
    with col_c2:
        sec_df = pd.DataFrame({
            "Resolver Category": ["Dominant Subnet (47.5% Traffic)", "Peripheral Small ISPs (52.5% Traffic)"],
            "DNSSEC Validation Rate (do=1)": [97.11, 78.99]
        })
        fig_sec = px.bar(
            sec_df, x="Resolver Category", y="DNSSEC Validation Rate (do=1)",
            text="DNSSEC Validation Rate (do=1)",
            color="Resolver Category",
            color_discrete_sequence=["#10B981", "#EF4444"],
            title="DNSSEC Validation Gap (DO Bit Requested)",
            template="plotly_dark"
        )
        fig_sec.update_traces(texttemplate='%{text:.2f}%', textposition='inside')
        fig_sec.update_yaxes(range=[60, 105])
        fig_sec.update_layout(margin=dict(l=30, r=30, t=50, b=30), showlegend=False)
        st.plotly_chart(fig_sec, use_container_width=True)
        st.error("**Security Gap Identified:** Non-dominant resolvers exhibit an **18.12 percentage point drop** in DNSSEC validation, leaving 21% of peripheral users vulnerable to DNS spoofing and cache poisoning.")

# TAB 4: IDADX THREAT HUNTER
with tab4:
    st.subheader("4. IDADX Threat Hunter: Sovereign Sector Subdomain Weaponization")
    st.markdown("""
    Cross-correlating the IDADX threat lexicon against ccTLD queries with strict regex matching reveals **946 active malicious domains**.
    **Critical Discovery:** Compromised government (`.go.id`) subdomains exhibit an absolute **100.0% resolution success rate (NOERROR = 756, NXDOMAIN = 0)**, while higher education (`.ac.id`) reaches **95.51% active resolution (NOERROR = 298, NXDOMAIN = 14)**, bringing the public sector average to **98.69% active**! These sites are actively serving gambling content from legitimate institutional nameservers.
    """)
    
    col_th1, col_th2 = st.columns([4, 6])
    with col_th1:
        fig_sec = px.bar(
            sectors_df, y="sector_category", x="unique_domains",
            orientation="h",
            text="unique_domains",
            title="Active Compromised Subdomains by Sector",
            labels={"sector_category": "Sector", "unique_domains": "Distinct Domains"},
            color="sector_category",
            color_discrete_sequence=px.colors.qualitative.Bold,
            template="plotly_dark"
        )
        fig_sec.update_traces(texttemplate='%{text}', textposition='outside')
        fig_sec.update_layout(yaxis=dict(autorange="reversed"), margin=dict(l=30, r=30, t=50, b=30), showlegend=False)
        st.plotly_chart(fig_sec, use_container_width=True)
    
    with col_th2:
        selected_sector = st.selectbox(
            "Filter Compromised Domains by Institutional Sector:",
            options=["All Sectors"] + list(sectors_df['sector_category'].unique()),
            index=1 # default to Government
        )
        
        filtered_threat = threat_df if selected_sector == "All Sectors" else threat_df[threat_df['sector_category'] == selected_sector]
        
        st.dataframe(
            filtered_threat[['clean_qname', 'query_count', 'count_noerror', 'distinct_resolvers', 'sector_category']].head(20),
            use_container_width=True,
            column_config={
                "clean_qname": "Compromised Domain / Subdomain",
                "query_count": "30-Min Queries",
                "count_noerror": "Live Resolved (NOERROR)",
                "distinct_resolvers": "Unique Resolvers",
                "sector_category": "Sector"
            }
        )
        
        csv_data = filtered_threat.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download Threat Registry for CSIRT Dispatch (CSV)",
            data=csv_data,
            file_name="pandi_idadx_compromised_subdomains.csv",
            mime="text/csv"
        )

# TAB 5: DGA & INFRASTRUCTURE RESILIENCE
with tab5:
    st.subheader("5. DGA Detection, Subdomain Entropy & MTU Amplification")
    st.markdown("""
    Detecting algorithmically generated domains (DGA) and response amplification risks across the national registry.
    """)
    
    col_d1, col_d2 = st.columns(2)
    with col_d1:
        st.write("**Top Algorithmic DGA Candidates Flagged (Entropy >= 3.6, SLD >= 14):**")
        st.dataframe(
            dga_df[['domain', 'sld', 'sld_length', 'shannon_entropy', 'total_queries', 'nxdomain_rate']].head(15),
            use_container_width=True,
            column_config={
                "domain": "Query Domain",
                "sld": "Second-Level Label",
                "sld_length": "Length",
                "shannon_entropy": st.column_config.NumberColumn("Entropy", format="%.2f"),
                "total_queries": "Queries",
                "nxdomain_rate": st.column_config.NumberColumn("NXDOMAIN %", format="%.1f%%")
            }
        )
    
    with col_d2:
        st.write("**Response Packet Size & MTU Fragmentation Risk:**")
        fig_size = px.bar(
            sizes_df, x="size_bin", y="packet_percentage",
            text="packet_percentage",
            title="Outbound Response Message Size Distribution",
            labels={"size_bin": "Size Category", "packet_percentage": "Share (%)"},
            color="packet_percentage",
            color_continuous_scale="Reds",
            template="plotly_dark"
        )
        fig_size.update_traces(texttemplate='%{text:.2f}%', textposition='outside')
        fig_size.update_layout(margin=dict(l=30, r=30, t=50, b=30), showlegend=False)
        st.plotly_chart(fig_size, use_container_width=True)
        st.info("Over **43.3% of responses exceed 512 bytes**, relying on EDNS0. However, **124,513 responses exceed 1,500 bytes**, which triggers IP packet fragmentation or TCP fallback.")

# FOOTER & STRATEGIC RECOMMENDATIONS
st.write("---")
st.subheader("Actionable Recommendations for PANDI Registry Operations")
col_r1, col_r2, col_r3 = st.columns(3)
with col_r1:
    st.markdown("""
    **1. Autonomous IDADX Subdomain Sentinel**
    - Deploy passive in-stream query regex matching at authoritative nodes.
    - Automated real-time alerts dispatched to BSSN and Gov-CSIRT within 60 seconds.
    - Policy for temporary registry sub-zone suspension for unaddressed judol subdomains.
    """)
with col_r2:
    st.markdown("""
    **2. Resolver Diversification & Peering SLAs**
    - Subnet `2d68:a529::/32` holds 47.5% concentration risk.
    - Deploy local Anycast nodes inside top tier-1 networks.
    - Establish bilateral BGP peering SLAs with guaranteed MTU <= 1232 bytes.
    """)
with col_r3:
    st.markdown("""
    **3. DNSSEC Mandatory Validation Campaign**
    - Peripheral ISPs have a 21% validation blind spot (78.99% DO rate).
    - PANDI registrar incentive: Discount domain registration fees for registrars enforcing DNSSEC validation.
    - National dashboard publicizing ISP DNSSEC health ratings.
    """)

st.caption("Pesta Data Nasional (PeDaS) 2026 Babak Final | All analyses strictly reproducible from official PANDI 30-minute DNS telemetry.")
