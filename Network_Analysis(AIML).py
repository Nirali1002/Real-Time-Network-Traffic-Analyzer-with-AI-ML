import streamlit as st
from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
from datetime import datetime
import threading, queue
from sklearn.ensemble import IsolationForest
import numpy as np
import altair as alt

st.set_page_config(layout="wide", page_title="AI-Powered Real-Time Network Analyzer")
st.title("🌐 Real-Time Network Traffic Analyzer with AI/ML")

# ----------------- Packet Queue -----------------
packet_queue = queue.Queue()
live_packets = []

# ----------------- Sidebar Controls -----------------
interval = st.sidebar.slider("Refresh interval (seconds)", 1, 5, 2)
max_table_rows = st.sidebar.slider("Max rows in table", 5, 20, 10)

# ----------------- Traffic Classification -----------------
def classify_traffic(proto, dst_port):
    if proto == "TCP":
        if dst_port in [80, 443]:
            return "Web"
        elif dst_port == 22:
            return "SSH"
        elif dst_port == 21:
            return "FTP"
        elif dst_port in [25, 587]:
            return "Email"
        else:
            return "Other_TCP"
    elif proto == "UDP":
        if dst_port == 53:
            return "DNS"
        elif dst_port in [67, 68]:
            return "DHCP"
        elif dst_port == 123:
            return "NTP"
        elif 5004 <= dst_port <= 5005:
            return "Streaming"
        else:
            return "Other_UDP"
    elif proto == "ICMP":
        return "Network_Control"
    else:
        return "Other"

# ----------------- Packet Sniffer -----------------
def packet_handler(pkt):
    proto = "Other"
    src_ip = dst_ip = src_port = dst_port = 0
    length = len(pkt)

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    if pkt.haslayer(TCP):
        proto = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"

    category = classify_traffic(proto, dst_port)

    packet_queue.put({
        "protocol": proto,
        "category": category,
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "length": int(length),
        "timestamp": datetime.now()
    })

def start_sniff():
    sniff(prn=packet_handler, store=False)

threading.Thread(target=start_sniff, daemon=True).start()

# ----------------- Isolation Forest -----------------
iso_model = IsolationForest(contamination=0.02, random_state=42)

# ----------------- Streamlit Placeholders -----------------
table_area = st.empty()
alert_area = st.empty()
chart_area = st.empty()

# ----------------- Live Loop -----------------
ip_stats = {}  # Aggregated stats per IP
live_data = []  # For line chart

while True:
    t0 = datetime.now()
    interval_packets = []

    # Collect packets for this interval
    while (datetime.now() - t0).seconds < interval:
        try:
            pkt = packet_queue.get(timeout=0.5)
            interval_packets.append(pkt)
            live_packets.append(pkt)
        except:
            pass

    if not live_packets:
        continue

    df = pd.DataFrame(live_packets)
    df["src_ip"] = df["src_ip"].astype(str)
    df["dst_ip"] = df["dst_ip"].astype(str)

    # ----------------- Aggregation for Isolation Forest -----------------
    ip_features = []
    ip_list = df["src_ip"].unique()
    for ip in ip_list:
        df_ip = df[df["src_ip"] == ip]
        packet_count = len(df_ip)
        unique_dst_ports = df_ip["dst_port"].nunique()
        avg_length = df_ip["length"].mean()
        tcp_ratio = (df_ip["protocol"]=="TCP").sum() / packet_count
        udp_ratio = (df_ip["protocol"]=="UDP").sum() / packet_count
        icmp_ratio = (df_ip["protocol"]=="ICMP").sum() / packet_count
        ip_features.append([packet_count, unique_dst_ports, avg_length, tcp_ratio, udp_ratio, icmp_ratio])
        ip_stats[ip] = [packet_count, unique_dst_ports, avg_length, tcp_ratio, udp_ratio, icmp_ratio]

    X = np.array(ip_features)
    if len(X) > 1:
        preds = iso_model.fit_predict(X)
        risk_scores = iso_model.decision_function(X)

        table_data = []
        for idx, ip in enumerate(ip_list):
            table_data.append({
                "src_ip": ip,
                "packet_count": ip_stats[ip][0],
                "unique_dst_ports": ip_stats[ip][1],
                "avg_length": round(ip_stats[ip][2],2),
                "TCP_ratio": round(ip_stats[ip][3],2),
                "UDP_ratio": round(ip_stats[ip][4],2),
                "ICMP_ratio": round(ip_stats[ip][5],2),
                "risk_score": round(risk_scores[idx],2),
                "malicious": "YES" if preds[idx]==-1 else "NO"
            })

        table_df = pd.DataFrame(table_data)

        # Highlight malicious IPs in red
        def highlight_malicious(row):
            return ['background-color: red' if row.malicious=="YES" else '' for _ in row]
        table_area.dataframe(table_df.style.apply(highlight_malicious, axis=1), height=400)

        # Alert section
        alerts = table_df[table_df["malicious"]=="YES"]
        if not alerts.empty:
            alert_area.markdown("### ⚠️ Malicious IPs Detected")
            for ip in alerts["src_ip"].values:
                alert_area.write(f"- {ip} is potentially malicious. Consider blocking or monitoring.")
        else:
            alert_area.empty()

    # ----------------- Prepare Data for Line Chart -----------------
    timestamp_now = datetime.now()
    category_counts = df.groupby("category").size().to_dict()

    row_chart = {"timestamp": timestamp_now}
    categories = ["Web","Streaming","DNS","SSH","FTP","Email","Network_Control","Other_TCP","Other_UDP","Other"]
    for cat in categories:
        row_chart[cat] = category_counts.get(cat, 0)
    live_data.append(row_chart)
    chart_df = pd.DataFrame(live_data)

    # ----------------- Line Chart for All Categories -----------------
    df_melt = chart_df.melt("timestamp", categories)
    line_chart = alt.Chart(df_melt).mark_line().encode(
        x="timestamp:T",
        y="value:Q",
        color="variable:N",
        tooltip=["variable","value","timestamp"]
    ).properties(title="Live Traffic Category Trends")
    chart_area.altair_chart(line_chart, use_container_width=True)
