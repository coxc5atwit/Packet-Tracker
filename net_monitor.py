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

#Optional: specify a particular capture interface, or leave None for default
INTERFACE = None
#Keeps only set amount of logs to avoid too large of a log file
MAX_LOGS = 200


class NetworkState:
    #Holds all of the monitors variables
    def __init__(self):
        #Prevents concurrent access issues
        self.lock = threading.Lock()
        self.running = False
        #Counters for the UI
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
    """Checks all packets and logs any with errors

    This function is called for every packet that Scapy delivers
    """

    with state.lock:
        #Increments the total packet counter
        state.packet_count += 1

        #Layer 2: Data Link
        try:
            if packet.haslayer(Ether) and packet[Ether].dst == "ff:ff:ff:ff:ff:ff":
                if not packet.haslayer(ARP) and not packet.haslayer(IP):
                    #Track broadcast packet with timestamp
                    current_time = time.time()
                    state.broadcast_window.append(current_time)
                    
                    #Check if we have excessive broadcasts in the last 5 seconds
                    #Remove packets older than 5 seconds from window for counting
                    recent_broadcasts = [t for t in state.broadcast_window if current_time - t < 5]
                    
                    #Alert if more than 20 non-IP broadcasts in 5 seconds, and avoid spam with 10 second cooldown
                    if len(recent_broadcasts) > 20 and (current_time - state.last_broadcast_alert) > 10:
                        state.layer_counts["Layer 2 (Data Link)"] += 1 
                        state.error_log.appendleft(
                            {"Time": time.strftime("%H:%M:%S"), "Layer": "L2", "Issue": f"Excessive Broadcast Traffic ({len(recent_broadcasts)} packets in 5s)"}
                        )
                        state.last_broadcast_alert = current_time
        except Exception:
            pass

        #Layer 3: Networt
        if packet.haslayer(ICMP):
            try:
                icmp_type = packet[ICMP].type
                if icmp_type == 3:  #Destination Unreachable
                    state.layer_counts["Layer 3 (Network)"] += 1
                    state.error_log.appendleft(
                        {
                            "Time": time.strftime("%H:%M:%S"),
                            "Layer": "L3",
                            "Issue": f"Dest Unreachable: {packet[IP].dst if packet.haslayer(IP) else 'unknown'}",
                        }
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
            
            #Check for a RST flag
            if 'R' in flags: 
                src_ip = packet[IP].src
                dst_port = packet[TCP].dport
                ttl_val = packet[IP].ttl 
                
                #Update state counts and log the detailed error
                state.layer_counts["Layer 4 (Transport)"] += 1
                state.error_log.appendleft(
                    {
                        "Time": time.strftime("%H:%M:%S"), 
                        "Layer": "L4", 
                        "Issue": f"TCP Reset. Source: {src_ip}, Port Rejected: {dst_port}, TTL: {ttl_val}"
                    }
                )

        #Layer 7: Application
        if packet.haslayer(DNS) and packet.haslayer(DNSRR):
            try:
                #rcode == 3 indicates NXDOMAIN
                if packet[DNS].rcode == 3:
                    state.layer_counts["Layer 7 (Application)"] += 1
                    state.error_log.appendleft(
                        {"Time": time.strftime("%H:%M:%S"), "Layer": "L7", "Issue": "DNS NXDOMAIN Error"}
                    )
            except Exception:
                pass


def layer_one_check():

    #Block that does the link layer 1 packet check
    while state.running:
        #Gets stats from the NICs
        stats = psutil.net_if_stats()
        #Iterate over known interfaces and detect DOWN state
        for iface, info in stats.items():
            try:
                if not info.isup and "Loopback" not in iface:
                    with state.lock:
                        state.layer_counts["Layer 1 (Physical)"] += 1
                        #Avoids the log getting spammed that it is down
                        if len(state.error_log) == 0 or state.error_log[0]["Issue"] != f"{iface} is DOWN":
                            state.error_log.appendleft(
                                {"Time": time.strftime("%H:%M:%S"), "Layer": "L1", "Issue": f"Interface {iface} is DOWN"}
                            )
            except Exception:
                continue
        #Waits some time between checks to avoid spamming the log
        time.sleep(60)


def start_sniffing():

    state.running = True

    #Start Layer 1 monitor in background
    l1_thread = threading.Thread(target=layer_one_check, daemon=True)
    l1_thread.start()

    #Start Scapy Sniffing.
    sniff(prn=analyze_packet, store=0, stop_filter=lambda x: not state.running)

#Streamlit UI

st.set_page_config(page_title="OSI Network Monitor", layout="wide")

st.title("OSI Layer Network Monitor")

#Sidebar Controls
st.sidebar.header("Controls")

if st.sidebar.button("Start Monitoring"):
    if not state.running:
        t = threading.Thread(target=start_sniffing, daemon=True)
        t.start()
        st.sidebar.success("Sniffer Started!")

if st.sidebar.button("Stop Monitoring"):
    state.running = False
    st.sidebar.warning("Sniffer Stopped!")


#Dashboard Layout
#Two-column layout is reserved for future controls/summary (currently unused)
col1, col2 = st.columns([2, 1])

#Placeholder container that we repeatedly replace to simulate a live dashboard
placeholder = st.empty()

while True:
    with placeholder.container():
        #Metrics row that show quick numeric indicators
        m1, m2, m3, m4, m5 = st.columns(5)
        with state.lock:
            total_pkts = state.packet_count
            counts = state.layer_counts.copy()
            recent_logs = list(state.error_log)

        #Simple numeric metrics for quick status checks
        m1.metric("Total Packets Scanned", total_pkts)
        m2.metric("L2 Data Errors", counts["Layer 2 (Data Link)"])
        m3.metric("L3 Network Errors", counts["Layer 3 (Network)"])
        m4.metric("L4 Transport Errors", counts["Layer 4 (Transport)"])
        m5.metric("L7 App Errors", counts["Layer 7 (Application)"])

        st.markdown("---")

        #Visualizations: bar chart for counts and a table for recent logs
        c1, c2 = st.columns(2)

        with c1:
            st.subheader("Errors by OSI Layer")
            #Convert the layer counters to a DataFrame and let Streamlit chart it
            df_counts = pd.DataFrame.from_dict(counts, orient='index', columns=['Count'])
            st.bar_chart(df_counts)

        with c2:
            st.subheader("Live Issue Log")
            if recent_logs:
                df_logs = pd.DataFrame(recent_logs)
                #Show the most recent issues in a scrollable data frame
                st.dataframe(df_logs, height=300, use_container_width=True)
            else:
                st.info("No errors detected yet.")

    #Sleep briefly to control UI update rate. Streamlit itself handles
    #re-rendering; this avoids burning CPU in a tight loop.
    time.sleep(1)