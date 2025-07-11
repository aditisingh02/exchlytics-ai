import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import streamlit as st
from analyzer.pcap_parser import parse_pcap
from analyzer.error_detector import detect_errors
from llm.ollama_client import query_llm
import json, tempfile
import glob
from main import generate_report 
import pandas as pd
import plotly.express as px
from pdf_report import create_pdf_report
import base64
from datetime import datetime

# session state for PDF generation
if 'pdf_generated' not in st.session_state:
    st.session_state.pdf_generated = False
if 'pdf_bytes' not in st.session_state:
    st.session_state.pdf_bytes = None
if 'pdf_filename' not in st.session_state:
    st.session_state.pdf_filename = None
if 'report_data' not in st.session_state:
    st.session_state.report_data = None

# --- UI Structure --- #
st.set_page_config(
    layout="centered", 
    page_title="Exchlytics AI",
    page_icon="🪼"
)

st.title("Exchlytics AI")
st.write("Intelligent PCAP Analysis for Trading Systems")

st.sidebar.title("Exchlytics AI")
st.sidebar.markdown("---")

demo_pcap_files = glob.glob("pcap_files/Demos/*.pcap")

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
### Features
- 🤖 AI-Powered Analysis
- 📊 Real-time Metrics
- 🔍 Advanced Error Detection
- ⚡ Latency Analysis
- 📈 Trading Pattern Analysis
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

if st.button("Run Analysis") and file_to_analyze:
    with st.spinner(f"Analyzing {os.path.basename(file_to_analyze)}..."):
        try:
            generate_report(file_to_analyze)
            # Load the generated report
            report_path = f"output/reports/{os.path.basename(file_to_analyze)}.json"
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    report_data = json.load(f)
                st.session_state.report_data = report_data  # Store in session state
                report_loaded = True
                st.success("Analysis complete and report loaded!")
            else:
                st.error("Analysis ran, but report file not found.")
        except Exception as e:
            st.error(f"An error occurred during analysis: {e}")

elif not file_to_analyze:
    st.info("Please select or upload a PCAP file to analyze.")

if st.session_state.report_data:  # Use session state data instead of local variable
    st.sidebar.markdown("---")
    st.sidebar.header("📄 Generate Report")
    
    def generate_pdf_report():
        try:
            os.makedirs('output/pdf_reports', exist_ok=True)
            
            # Generate PDF report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"analysis_report_{timestamp}.pdf"
            pdf_path = os.path.join('output/pdf_reports', pdf_filename)
            
            with st.spinner('Generating PDF report...'):
                create_pdf_report(st.session_state.report_data, pdf_path)
                
                # Read the generated PDF
                with open(pdf_path, "rb") as f:
                    pdf_bytes = f.read()
                
                # Store in session state
                st.session_state.pdf_generated = True
                st.session_state.pdf_bytes = pdf_bytes
                st.session_state.pdf_filename = pdf_filename
            
            return True
        except Exception as e:
            st.error(f"Error generating PDF report: {e}")
            st.session_state.pdf_generated = False
            st.session_state.pdf_bytes = None
            st.session_state.pdf_filename = None
            return False

    # Generate PDF button with callback
    if st.sidebar.button("Generate PDF Report", key="generate_pdf"):
        if generate_pdf_report():
            st.sidebar.success("PDF report generated successfully!")
    #if generated, show download button
    if st.session_state.pdf_generated and st.session_state.pdf_bytes:
        st.sidebar.download_button(
            label="Download PDF Report",
            data=st.session_state.pdf_bytes,
            file_name=st.session_state.pdf_filename,
            mime="application/pdf",
            key="download_pdf"
        )

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
            with st.container(border=True):
                session_key = lat['session']
                
                formatted_session = f"{session_key[0]}:{session_key[1]} -> {session_key[2]}:{session_key[3]}"
                st.markdown(f"**Session {i+1}:** {formatted_session}")
                st.markdown(f"**Latency:** {lat['latency_ms']:.2f} ms")
    else:
        st.info("No latency data available.")

# Clean up temp file if it was created
if uploaded_file and file_to_analyze and os.path.exists(file_to_analyze) and file_to_analyze.startswith(tempfile.gettempdir()):
    os.remove(file_to_analyze)

# Footer
st.markdown("---")
st.markdown("""
    <div style='text-align: center'>
        <p>Exchlytics AI - Where AI meets Trading Intelligence</p>
        <p>Built with ❤️ by <a href='https://github.com/aditisingh02'>Aditi Singh</a></p>
    </div>
""", unsafe_allow_html=True) 