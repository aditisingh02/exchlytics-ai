from analyzer.error_detector import detect_errors

def test_detect_errors():
    packets = [
        {'payload_len': 0, 'flags': '', 'src_ip': '1.1.1.1'},
        {'payload_len': 10, 'flags': 'R', 'src_ip': '2.2.2.2'},
        {'payload_len': 5, 'flags': '', 'src_ip': '3.3.3.3'},
    ]
    issues = detect_errors(packets)
    assert any(i['type'] == 'Bogus TCP Payload' for i in issues)
    assert any(i['type'] == 'Session Reset' for i in issues) 