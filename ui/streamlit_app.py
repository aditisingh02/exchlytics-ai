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
- Packet loss analysis
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
    
    # Basic Packet Loss indication (can be refined with more sophisticated logic)
    packet_loss_info = f"{tcp_retransmissions_count} retransmissions detected (indicates potential loss)" if tcp_retransmissions_count > 0 else "No retransmissions detected"

    # Order Latency Display Refinement
    all_latencies_ms = [lat['latency_ms'] for lat in report_data.get('latencies', []) if 'latency_ms' in lat]
    if all_latencies_ms:
        avg_latency = sum(all_latencies_ms) / len(all_latencies_ms)
        min_latency = min(all_latencies_ms)
        max_latency = max(all_latencies_ms)
        order_latency_info = f"Avg: {avg_latency:.2f}ms, Min: {min_latency:.2f}ms, Max: {max_latency:.2f}ms"
    else:
        order_latency_info = "N/A"

    col_stats1, col_stats2, col_stats3 = st.columns(3)
    with col_stats1:
        st.metric(label="Total Packets", value=total_packets)
    with col_stats2:
        st.metric(label="TCP Retransmissions", value=tcp_retransmissions_count)
    with col_stats3:
        st.metric(label="Packet Loss", value=tcp_retransmissions_count)
        if tcp_retransmissions_count > 0:
            st.markdown(f"{packet_loss_info.split(' ', 1)[1]}")
        else:
            st.markdown(f"{packet_loss_info}")

    st.markdown("**Order Latency:**")
    if all_latencies_ms:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(label="Average Latency", value=f"{avg_latency:.2f} ms")
        with col2:
            st.metric(label="Minimum Latency", value=f"{min_latency:.2f} ms")
        with col3:
            st.metric(label="Maximum Latency", value=f"{max_latency:.2f} ms")
    else:
        st.info("No order latency data available.")

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
            with st.container(border=True): # Use st.container to create a visual card
                session_key = lat['session']
                # Format session key for better readability
                formatted_session = f"{session_key[0]}:{session_key[1]} -> {session_key[2]}:{session_key[3]}"
                st.markdown(f"**Session {i+1}:** {formatted_session}")
                st.markdown(f"**Latency:** {lat['latency_ms']:.2f} ms")
    else:
        st.info("No latency data available.")

# Clean up temp file if it was created
if uploaded_file and file_to_analyze and os.path.exists(file_to_analyze) and file_to_analyze.startswith(tempfile.gettempdir()):
    os.remove(file_to_analyze) 