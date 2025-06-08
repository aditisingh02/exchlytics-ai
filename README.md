# Exchlytics AI: Intelligent PCAP Analysis for Trading Systems

https://github.com/user-attachments/assets/c02f73e2-60e5-4da7-89b3-873b5688415e

## Overview

Exchlytics AI is a cutting-edge PCAP analysis tool specifically designed for financial trading systems. It combines the power of AI with advanced packet analysis to provide real-time insights into trading operations, latency issues, and system performance.

## Features

### Core Capabilities

- AI-powered packet analysis using Microsoft's Phi model
- Advanced anomaly detection
- Interactive visualizations
- Natural language interface
- Automated report generation

### Trading-Specific Analysis

- Order execution latency tracking
- Rejection reason analysis
- Session stability monitoring
- Performance bottleneck detection
- Trading pattern analysis

## Technical Stack

- **Frontend**: Streamlit
- **Packet Analysis**: Scapy, PyShark
- **AI/ML**: Microsoft Phi, Azure AI
- **Data Processing**: Python 3.9
- **Visualization**: Plotly
- **Local AI**: Ollama

## Getting Started

### Prerequisites

- Python 3.9
- Conda
- Ollama (for local AI models)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/exchlytics-ai.git
cd exchlytics-ai
```

2. Create and activate the conda environment:

```bash
conda env create -f environment.yml
conda activate pcap-analyzer-env
```

3. Install Ollama and pull the required model:

```bash
# Follow instructions at https://ollama.com/ for your OS
ollama pull phi:latest
```

4. Run the application:

```bash
streamlit run app.py
```

## Usage

### Basic Analysis

1. Upload your PCAP file through the Streamlit interface
2. Select analysis parameters
3. View real-time results and insights

### Advanced Features

- Use natural language queries to analyze specific aspects
- Generate detailed reports
- Export analysis results
- Monitor real-time trading metrics

## Key Benefits

- 90% faster analysis time
- Reduced manual intervention
- Improved trading efficiency
- Enhanced compliance monitoring
- Better risk management

## Configuration

The application can be configured through:

- `config.yaml` for general settings
- Environment variables for sensitive data
- UI settings for analysis parameters

---

_"Where AI meets Trading Intelligence"_
