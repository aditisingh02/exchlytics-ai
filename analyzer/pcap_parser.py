import pyshark
from scapy.all import rdpcap
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_pcap(file_path):
    data = []
    try:
        # Use display filter to only capture TCP packets
        cap = pyshark.FileCapture(file_path, display_filter='tcp')
        logger.info("Starting PCAP parsing with Pyshark...")
        
        for pkt in cap:
            try:
                if not hasattr(pkt, 'ip') or not hasattr(pkt, 'tcp'):
                    continue
                    
                # Extract only essential fields
                data.append({
                    'src_ip': pkt.ip.src,
                    'dst_ip': pkt.ip.dst,
                    'src_port': int(pkt.tcp.srcport),
                    'dst_port': int(pkt.tcp.dstport),
                    'flags': pkt.tcp.flags,
                    'seq': int(pkt.tcp.seq),
                    'ack': int(pkt.tcp.ack),
                    'payload_len': len(pkt.tcp.payload.raw_value) // 2 if hasattr(pkt.tcp.payload, 'raw_value') else 0,
                    'header_len': int(pkt.tcp.hdr_len) if hasattr(pkt.tcp, 'hdr_len') else 20,
                    'checksum': int(pkt.tcp.checksum, 16) if hasattr(pkt.tcp, 'checksum') else None,
                    'options': pkt.tcp.options if hasattr(pkt.tcp, 'options') else [],
                    'raw_payload': bytes.fromhex(pkt.tcp.payload.raw_value) if hasattr(pkt.tcp.payload, 'raw_value') else b'',
                    'timestamp': float(pkt.sniff_time.timestamp()) if hasattr(pkt, 'sniff_time') else None,
                })
            except Exception as packet_error:
                logger.warning(f"Error parsing packet: {packet_error}")
                continue
                
        cap.close()
        logger.info(f"Successfully parsed {len(data)} packets with Pyshark")
        return data
        
    except Exception as e:
        logger.warning(f"Error parsing PCAP with Pyshark: {e}")
        logger.info("Falling back to Scapy for parsing...")
        
        try:
            packets = rdpcap(file_path)
            data = []
            for pkt in packets:
                try:
                    if 'IP' not in pkt or 'TCP' not in pkt:
                        continue
                        
                    data.append({
                        'src_ip': pkt['IP'].src,
                        'dst_ip': pkt['IP'].dst,
                        'src_port': pkt['TCP'].sport,
                        'dst_port': pkt['TCP'].dport,
                        'flags': str(pkt['TCP'].flags),
                        'seq': pkt['TCP'].seq,
                        'ack': pkt['TCP'].ack,
                        'payload_len': len(pkt['TCP'].payload),
                        'header_len': pkt['TCP'].dataofs if hasattr(pkt['TCP'], 'dataofs') else 20,
                        'checksum': pkt['TCP'].chksum if hasattr(pkt['TCP'], 'chksum') else None,
                        'options': pkt['TCP'].options if hasattr(pkt['TCP'], 'options') else [],
                        'raw_payload': bytes(pkt['TCP'].payload),
                        'timestamp': float(pkt.time) if hasattr(pkt, 'time') else None,
                    })
                except Exception as packet_error:
                    logger.warning(f"Error parsing packet with Scapy: {packet_error}")
                    continue
                    
            logger.info(f"Successfully parsed {len(data)} packets with Scapy")
            return data
            
        except Exception as scapy_e:
            logger.error(f"Error falling back to Scapy: {scapy_e}")
            return [] 