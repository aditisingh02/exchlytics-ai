# Placeholder for latency calculation between order and response

def calculate_latency(packets):
    # Group packets by session (src_ip, src_port, dst_ip, dst_port)
    from collections import defaultdict
    import time
    sessions = defaultdict(list)
    for pkt in packets:
        sess_key = (pkt['src_ip'], pkt['src_port'], pkt['dst_ip'], pkt['dst_port'])
        sessions[sess_key].append(pkt)
    latencies = []
    for sess, pkts in sessions.items():
        if len(pkts) > 1:
            # Assume packets are in order; use first and last for rough latency
            start = pkts[0].get('timestamp', None)
            end = pkts[-1].get('timestamp', None)
            if start is not None and end is not None:
                latencies.append({'session': sess, 'latency_ms': (end - start) * 1000})
    return latencies 