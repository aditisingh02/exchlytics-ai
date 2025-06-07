import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import streamlit as st
from analyzer.pcap_parser import parse_pcap
from analyzer.error_detector import detect_errors
from llm.ollama_client import query_llm
import json, tempfile
import glob
from main import generate_report # Import the generate_report function
import pandas as pd
import plotly.express as px

# --- UI Structure --- #
st.set_page_config(layout="centered", page_title="PCAP Trading Data Analyzer")

st.title("PCAP Trading Data Analyzer")
st.write("Analyze PCAP files containing Exchange Trading Data")

# --- Sidebar for File Selection and Features --- #
st.sidebar.title("File Selection")

# List available demo PCAP files
demo_pcap_files = glob.glob("pcap_files/Demos/*.pcap")
# Prepend a default option
demo_pcap_options = ["-- Select a demo PCAP --"] + sorted(demo_pcap_files)
selected_demo_pcap = st.sidebar.selectbox("Select a demo PCAP File", demo_pcap_options)

uploaded_file = st.sidebar.file_uploader("Or upload your own PCAP file", type=['pcap'])

file_to_analyze = None
if selected_demo_pcap != "-- Select a demo PCAP --":
    file_to_analyze = selected_demo_pcap
elif uploaded_file:
    # Save uploaded file to a temp file for analysis
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        file_to_analyze = tmp_file.name

st.sidebar.markdown("""
This tool analyzes PCAP files
containing Exchange Trading Data.

Features:
- TCP retransmission detection
- Packet loss analysis (placeholder)
- Order latency measurement
- Comprehensive reporting
""")

# --- Main Content Area --- #
st.header("Basic Statistics")

# Initialize placeholders for statistics
total_packets = 0
tcp_retransmissions_count = 0
packet_loss_info = "N/A"
order_latency_info = "N/A"

report_loaded = False
report_data = {}

# Run Analysis button (or load report if already generated)
if st.button("Run Analysis") and file_to_analyze:
    with st.spinner(f"Analyzing {os.path.basename(file_to_analyze)}..."):
        try:
            generate_report(file_to_analyze)
            # Load the generated report
            report_path = f"output/reports/{os.path.basename(file_to_analyze)}.json"
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    report_data = json.load(f)
                report_loaded = True
                st.success("Analysis complete and report loaded!")
            else:
                st.error("Analysis ran, but report file not found.")
        except Exception as e:
            st.error(f"An error occurred during analysis: {e}")

elif not file_to_analyze:
    st.info("Please select or upload a PCAP file to analyze.")

# --- Display Statistics from loaded report --- #
if report_loaded:
    total_packets = report_data.get('total_packets', 0)
    tcp_retransmissions_count = len([err for err in report_data.get('errors', []) if err['type'] == 'TCP Retransmission'])
    # Placeholders for packet loss and order latency (actual calculation in latency_checker.py)
    # You'd integrate more sophisticated logic here if packet_loss_info is to be derived

    st.markdown(f"**Total Packets:** {total_packets}")
    st.markdown(f"**TCP Retransmissions:** {tcp_retransmissions_count}")
    st.markdown(f"**Packet Loss:** {packet_loss_info}")
    st.markdown(f"**Order Latency:** {order_latency_info}")

    st.header("📈 Visual Insights")

    # Error Type Distribution
    errors_df = pd.DataFrame(report_data.get('errors', []))
    if not errors_df.empty:
        error_counts = errors_df['type'].value_counts().reset_index()
        error_counts.columns = ['Error Type', 'Count']
        fig_errors = px.bar(error_counts, x='Error Type', y='Count', title='Distribution of Detected Error Types')
        st.plotly_chart(fig_errors)

    # Latency Distribution
    latencies_df = pd.DataFrame(report_data.get('latencies', []))
    if not latencies_df.empty:
        fig_latency = px.histogram(latencies_df, x='latency_ms', nbins=10, title='Latency Distribution (ms)', labels={'latency_ms': 'Latency (ms)'})
        st.plotly_chart(fig_latency)

    # FIX Message Type Breakdown (requires 'MsgType' in decoded FIX messages)
    fix_msgs_df = pd.DataFrame(report_data.get('fix_messages', []))
    if not fix_msgs_df.empty and '35' in fix_msgs_df.columns: # '35' is the MsgType tag in FIX
        msg_type_counts = fix_msgs_df['35'].value_counts().reset_index()
        msg_type_counts.columns = ['FIX Message Type', 'Count']
        fig_fix_types = px.bar(msg_type_counts, x='FIX Message Type', y='Count', title='Distribution of FIX Message Types')
        st.plotly_chart(fig_fix_types)
    elif not fix_msgs_df.empty and '35' not in fix_msgs_df.columns:
        st.info("FIX messages were decoded, but 'MsgType' (tag 35) was not found for visualization.")

    st.header("📊 Detected Issues")
    if report_data.get('errors'):
        for i, err in enumerate(report_data['errors']):
            with st.expander(f"Error {i+1}: {err['type']} - Packet {err['details'].get('seq', 'N/A')}"):
                st.json(err['details'])
                if 'llm_response' in err:
                    st.subheader("AI Insight")
                    st.write(err['llm_response'])
                else:
                    st.info("No AI insight available for this error.")
    else:
        st.info("No issues detected in this PCAP.")

    st.header("⏱️ Latency Analysis")
    if report_data.get('latencies'):
        for i, lat in enumerate(report_data['latencies']):
            st.write(f"Session {i+1}: {lat}")
    else:
        st.info("No latency data available.")

    st.header("📝 Decoded FIX Messages")
    if report_data.get('fix_messages'):
        for i, fix_msg in enumerate(report_data['fix_messages']):
            if fix_msg and not fix_msg.get('error'):
                st.json(fix_msg)
            elif fix_msg.get('error'):
                st.warning(f"Error decoding FIX message {i+1}: {fix_msg['error']}")
    else:
        st.info("No FIX messages found or decoded.")

# Clean up temp file if it was created
if uploaded_file and file_to_analyze and os.path.exists(file_to_analyze) and file_to_analyze.startswith(tempfile.gettempdir()):
    os.remove(file_to_analyze) 