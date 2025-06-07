from analyzer.pcap_parser import parse_pcap
from analyzer.error_detector import detect_errors
from analyzer.latency_checker import calculate_latency
from llm.ollama_client import query_llm
import json, os, sys, copy, binascii
import logging
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def bytes_to_hex(obj):
    if isinstance(obj, dict):
        return {k: bytes_to_hex(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [bytes_to_hex(i) for i in obj]
    elif isinstance(obj, tuple):
        return tuple(bytes_to_hex(i) for i in obj)
    elif isinstance(obj, bytes):
        return binascii.hexlify(obj).decode()
    else:
        return obj

def process_error(err):
    err_for_llm = copy.deepcopy(err)
    err_for_llm = bytes_to_hex(err_for_llm)
    
    prompt = f"""You are a network engineer specializing in equity trading systems.\nAnalyze this packet summary for signs of TCP-level errors, session mismanagement,\nor malformed trading messages (e.g., FIX). Explain the anomalies, their likely causes,\nand provide recommended remediation steps.\n\nPacket Summary: {json.dumps(err_for_llm)}"""
    ai_insight = query_llm(prompt)
    err['llm_response'] = ai_insight
    return err

def generate_report(pcap_file):
    logger.info(f"Starting analysis of {pcap_file}")
    
    # Parse PCAP file
    packets = parse_pcap(pcap_file)
    if not packets:
        logger.error("No packets were parsed successfully")
        return
        
    logger.info(f"Found {len(packets)} packets to analyze")
    
    # Detect errors and calculate latencies in parallel
    with ThreadPoolExecutor(max_workers=2) as executor:
        errors_future = executor.submit(detect_errors, packets)
        latencies_future = executor.submit(calculate_latency, packets)
        
        errors = errors_future.result()
        latencies = latencies_future.result()
    
    logger.info(f"Detected {len(errors)} errors and {len(latencies)} latency measurements")
    
    # Process errors with LLM in parallel
    with ThreadPoolExecutor() as executor:
        full_report = list(tqdm(
            executor.map(process_error, errors),
            total=len(errors),
            desc="Analyzing errors with LLM"
        ))
    
    # Save report
    os.makedirs('output/reports', exist_ok=True)
    output_path = f"output/reports/{os.path.basename(pcap_file)}.json"
    report_data = {
        'errors': full_report,
        'latencies': latencies,
        'total_packets': len(packets)
    }
    report_data = bytes_to_hex(report_data)
    
    with open(output_path, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    logger.info(f"Report saved to {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_pcap>")
        sys.exit(1)
    generate_report(sys.argv[1])