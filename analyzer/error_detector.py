def detect_errors(packet_list):
    issues = []
    session_tracker = {}
    for pkt in packet_list:
        sess_key = (pkt['src_ip'], pkt['src_port'], pkt['dst_ip'], pkt['dst_port'])
        # Track sequence numbers for retransmission
        if sess_key not in session_tracker:
            session_tracker[sess_key] = set()
        if pkt['seq'] in session_tracker[sess_key]:
            issues.append({
                'type': 'TCP Retransmission',
                'details': pkt
            })
        else:
            session_tracker[sess_key].add(pkt['seq'])
        # Bogus TCP Payload
        if pkt['payload_len'] == 0:
            issues.append({
                'type': 'Bogus TCP Payload',
                'details': pkt
            })
        # Session Reset
        if 'R' in pkt['flags']:
            issues.append({
                'type': 'Session Reset',
                'details': pkt
            })
        # Bogus header length (should be at least 20 bytes)
        if pkt.get('header_len') is not None and pkt['header_len'] < 5:
            issues.append({
                'type': 'Bogus TCP Header Length',
                'details': pkt
            })
        # Invalid checksum (0 or None is suspicious)
        if pkt.get('checksum') in [0, None]:
            issues.append({
                'type': 'Invalid TCP Checksum',
                'details': pkt
            })
        # FIN misuse (FIN without proper session end)
        if 'F' in pkt['flags'] and pkt['payload_len'] > 0:
            issues.append({
                'type': 'FIN with Data (Possible Misuse)',
                'details': pkt
            })
    return issues 