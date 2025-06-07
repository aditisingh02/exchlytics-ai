from scapy.all import rdpcap

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    data = []
    for pkt in packets:
        if 'IP' in pkt and 'TCP' in pkt:
            data.append({
                'src_ip': pkt['IP'].src,
                'dst_ip': pkt['IP'].dst,
                'src_port': pkt['TCP'].sport,
                'dst_port': pkt['TCP'].dport,
                'flags': str(pkt['TCP'].flags),
                'seq': pkt['TCP'].seq,
                'ack': pkt['TCP'].ack,
                'payload_len': len(pkt['TCP'].payload),
                'header_len': pkt['TCP'].dataofs if hasattr(pkt['TCP'], 'dataofs') else None,
                'checksum': pkt['TCP'].chksum if hasattr(pkt['TCP'], 'chksum') else None,
                'options': pkt['TCP'].options if hasattr(pkt['TCP'], 'options') else None,
                'raw_payload': bytes(pkt['TCP'].payload),
                'timestamp': float(pkt.time) if hasattr(pkt, 'time') else None,
            })
    return data 