"""
net_monitor.py

A small Streamlit-based network monitoring demo that maps observed
packet characteristics to OSI layers and logs suspicious events.

Requirements to run:

1. Install Npcap for windows.
2. Run "pip install scapy streamlit pandas psutil plotly" in your terminal as administrator to install scapy and etc.
3. Run "python -m streamlit run net_monitor.py" in the same directory as this file.

After running that command it will automatically open a browser window with the dashboard.

Use for testing:
tracert -h 1 google.com
"""
import streamlit as st
import pandas as pd
import psutil
import time
import threading
from collections import deque
from scapy.all import sniff, IP, TCP, ICMP, ARP, DNS, DNSRR, Ether

#Keeps only set amount of logs to avoid too large of a log file
MAX_LOGS = 200

class NetworkState:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.selected_interface = None
        self.layer_counts = {
            "Layer 1 (Physical)": 0,
            "Layer 2 (Data Link)": 0,
            "Layer 3 (Network)": 0,
            "Layer 4 (Transport)": 0,
            "Layer 7 (Application)": 0,
        }
        self.error_log = deque(maxlen=MAX_LOGS)
        self.packet_count = 0
        self.broadcast_window = deque(maxlen=100)
        self.last_broadcast_alert = 0

state = NetworkState()

def analyze_packet(packet):
    """Checks all packets and logs any with errors"""
    with state.lock:
        state.packet_count += 1

        #Layer 2: Data Link
        try:
            if packet.haslayer(Ether) and packet[Ether].dst == "ff:ff:ff:ff:ff:ff":
                current_time = time.time()
                state.broadcast_window.append(current_time)
                
                recent_broadcasts = [t for t in state.broadcast_window if current_time - t < 5]
                    
                if len(recent_broadcasts) > 20 and (current_time - state.last_broadcast_alert) > 10:
                    state.layer_counts["Layer 2 (Data Link)"] += 1 
                    state.error_log.appendleft(
                        {"Time": time.strftime("%H:%M:%S"), "Layer": "L2", "Issue": f"Excessive Broadcast Traffic ({len(recent_broadcasts)} packets in 5s)"}
                    )
                    state.last_broadcast_alert = current_time
        except Exception:
            pass

        #Layer 3: Network
        if packet.haslayer(ICMP):
            try:
                icmp_type = packet[ICMP].type
                if icmp_type == 3:  #Destination Unreachable
                    state.layer_counts["Layer 3 (Network)"] += 1
                    state.error_log.appendleft(
                        {"Time": time.strftime("%H:%M:%S"), "Layer": "L3", "Issue": f"Dest Unreachable: {packet[IP].dst if packet.haslayer(IP) else 'unknown'}"}
                    )
                elif icmp_type == 11:  #Time to live exceeded
                    state.layer_counts["Layer 3 (Network)"] += 1
                    state.error_log.appendleft(
                        {"Time": time.strftime("%H:%M:%S"), "Layer": "L3", "Issue": "TTL Exceeded"}
                    )
            except Exception:
                pass

        #Layer 4: Transport
        if packet.haslayer(TCP) and packet.haslayer(IP):
            flags = packet[TCP].flags
            if 'R' in flags: 
                src_ip = packet[IP].src
                dst_port = packet[TCP].dport
                ttl_val = packet[IP].ttl 
                state.layer_counts["Layer 4 (Transport)"] += 1
                state.error_log.appendleft(
                    {"Time": time.strftime("%H:%M:%S"), "Layer": "L4", "Issue": f"TCP Reset. Source: {src_ip}, Port: {dst_port}, TTL: {ttl_val}"}
                )
        #Layer 7: Application
        if packet.haslayer(DNS):
            try:
                if getattr(packet[DNS], 'qr', 0) == 1 and getattr(packet[DNS], 'rcode', 0) == 3:
                    state.layer_counts["Layer 7 (Application)"] += 1
                    state.error_log.appendleft(
                        {"Time": time.strftime("%H:%M:%S"), "Layer": "L7", "Issue": "DNS NXDOMAIN Error"}
                    )
            except Exception:
                pass

def layer_one_check():
    """Independent thread for checking L1 interface status"""
    while state.running:
        try:
            stats = psutil.net_if_stats()
            for iface, info in stats.items():
                if not info.isup and "Loopback" not in iface:
                    with state.lock:
                        state.layer_counts["Layer 1 (Physical)"] += 1
                        #Prevent log spam
                        if len(state.error_log) == 0 or state.error_log[0]["Issue"] != f"{iface} is DOWN":
                            state.error_log.appendleft(
                                {"Time": time.strftime("%H:%M:%S"), "Layer": "L1", "Issue": f"Interface {iface} is DOWN"}
                            )
        except Exception:
            pass
        time.sleep(60)

def start_sniffing():
    state.running = True
    
    #Start Layer 1 monitor
    l1_thread = threading.Thread(target=layer_one_check, daemon=True)
    l1_thread.start()

    try:
        sniff(
            iface=state.selected_interface,
            prn=analyze_packet, 
            store=0, 
            stop_filter=lambda x: not state.running
        )
    except Exception as e:
        with state.lock:
             state.error_log.appendleft(
                 {"Time": time.strftime("%H:%M:%S"), "Layer": "System", "Issue": f"Sniffer Error: {e}"}
             )
        state.running = False

#Streamlit UI

st.set_page_config(page_title="OSI Network Monitor", layout="wide")
st.title("OSI Layer Network Monitor")

#Sidebar Controls
st.sidebar.header("Controls")

#Get list of interfaces for the dropdown
if_names = list(psutil.net_if_addrs().keys())
#Try to find a sensible default (like Wi-Fi or Ethernet)
default_ix = 0
for i, name in enumerate(if_names):
    if "Wi-Fi" in name or "Ethernet" in name:
        default_ix = i
        break

selected_iface = st.sidebar.selectbox("Select Interface", if_names, index=default_ix)

if st.sidebar.button("Start Monitoring"):
    if not state.running:
        state.selected_interface = selected_iface #Set the interface
        t = threading.Thread(target=start_sniffing, daemon=True)
        t.start()
        st.sidebar.success(f"Sniffer Started on {selected_iface}!")

if st.sidebar.button("Stop Monitoring"):
    state.running = False
    st.sidebar.warning("Sniffer Stopping...")

#Dashboard Layout
col1, col2 = st.columns([2, 1])
placeholder = st.empty()

while True:
    with placeholder.container():
        #Metrics row
        m1, m2, m3, m4, m5 = st.columns(5)
        with state.lock:
            total_pkts = state.packet_count
            counts = state.layer_counts.copy()
            recent_logs = list(state.error_log)

        m1.metric("Total Packets", total_pkts)
        m2.metric("L2 Errors", counts["Layer 2 (Data Link)"])
        m3.metric("L3 Errors", counts["Layer 3 (Network)"])
        m4.metric("L4 Errors", counts["Layer 4 (Transport)"])
        m5.metric("L7 Errors", counts["Layer 7 (Application)"])

        st.markdown("---")

        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Errors by OSI Layer")
            df_counts = pd.DataFrame.from_dict(counts, orient='index', columns=['Count'])
            st.bar_chart(df_counts)

        with c2:
            st.subheader("Live Issue Log")
            if recent_logs:
                df_logs = pd.DataFrame(recent_logs)
                st.dataframe(df_logs, height=300, use_container_width=True)
            else:
                st.info(f"Monitoring {state.selected_interface if state.running else '...'}")

    time.sleep(1)