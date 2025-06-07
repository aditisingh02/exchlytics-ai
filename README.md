# PCAP Reporting AI Tool

Automated anomaly detection and AI-powered reporting for exchange trading PCAP files.

## Features

- Parses PCAP files (Scapy/Pyshark)
- Detects TCP/IP and trading protocol anomalies
- AI explanations and remediation (Ollama/Azure Foundry)
- Optional Streamlit UI for interactive analysis

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. (Optional) Install and run Ollama for local LLM:
   - [Ollama Download](https://ollama.com)
   - Start with: `ollama run phi`

## Usage

- Run main analysis:
  ```bash
  python main.py <path_to_pcap>
  ```
- Launch UI:
  ```bash
  streamlit run ui/streamlit_app.py
  ```

## Project Structure

- `analyzer/` - PCAP parsing, error detection, protocol decoding
- `llm/` - LLM client for AI explanations
- `ui/` - Streamlit app (optional)
- `output/reports/` - Generated reports
