from analyzer.pcap_parser import parse_pcap
from analyzer.error_detector import detect_errors
from analyzer.latency_checker import calculate_latency
from analyzer.fix_decoder import decode_fix_message
from llm.ollama_client import query_llm
import json, os, sys, copy, binascii

def bytes_to_hex(obj):
    if isinstance(obj, dict):
        return {k: bytes_to_hex(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [bytes_to_hex(i) for i in obj]
    elif isinstance(obj, bytes):
        return binascii.hexlify(obj).decode()
    else:
        return obj

def generate_report(pcap_file):
    packets = parse_pcap(pcap_file)
    errors = detect_errors(packets)
    latencies = calculate_latency(packets)
    fix_msgs = [decode_fix_message(pkt['raw_payload']) for pkt in packets if pkt['raw_payload']]

    full_report = []
    for err in errors:
        # Make a copy and convert bytes to hex string for LLM prompt
        err_for_llm = copy.deepcopy(err)
        details = err_for_llm.get('details', {})
        if 'raw_payload' in details and isinstance(details['raw_payload'], bytes):
            details['raw_payload'] = binascii.hexlify(details['raw_payload']).decode()
        prompt = f"Analyze this TCP error: {json.dumps(err_for_llm)}"
        ai_insight = query_llm(prompt)
        err['llm_response'] = ai_insight
        full_report.append(err)

    os.makedirs('output/reports', exist_ok=True)
    output_path = f"output/reports/{os.path.basename(pcap_file)}.json"
    report_data = {
        'errors': full_report,
        'latencies': latencies,
        'fix_messages': fix_msgs
    }
    report_data = bytes_to_hex(report_data)
    with open(output_path, 'w') as f:
        json.dump(report_data, f, indent=2)

    print(f"Report saved to {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_pcap>")
        sys.exit(1)
    generate_report(sys.argv[1])