import pytest
from analyzer.pcap_parser import parse_pcap

def test_parse_pcap_returns_list(monkeypatch):
    # Mock rdpcap to return a list of fake packets
    class FakePkt:
        def __getitem__(self, item):
            if item == 'IP':
                class IP:
                    src = '1.1.1.1'
                    dst = '2.2.2.2'
                return IP()
            if item == 'TCP':
                class TCP:
                    sport = 1234
                    dport = 4321
                    flags = 'S'
                    seq = 1
                    ack = 0
                    payload = b'abc'
                return TCP()
    monkeypatch.setattr('scapy.all.rdpcap', lambda x: [FakePkt()])
    result = parse_pcap('dummy.pcap')
    assert isinstance(result, list)
    assert result[0]['src_ip'] == '1.1.1.1'
    assert result[0]['dst_ip'] == '2.2.2.2' 