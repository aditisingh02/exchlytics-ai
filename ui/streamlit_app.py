import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import streamlit as st
from analyzer.pcap_parser import parse_pcap
from analyzer.error_detector import detect_errors
from llm.ollama_client import query_llm
import json, tempfile

st.title("🧠 PCAP Exchange Analyzer")

uploaded = st.file_uploader("Upload a PCAP file", type=['pcap'])

if uploaded:
    st.success("File uploaded. Analyzing...")
    # Save uploaded file to a temp file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    packets = parse_pcap(tmp_path)
    errors = detect_errors(packets)
    report = []

    for err in errors:
        insight = query_llm(f"Explain this: {json.dumps(err)}")
        err['ai_insight'] = insight
        report.append(err)

    st.subheader("📊 Detected Issues")
    for r in report:
        st.write(f"**{r['type']}**")
        st.code(r['ai_insight'], language='markdown') 