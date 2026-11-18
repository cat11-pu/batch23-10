import pytest
import ipaddress
from acl.ip_acl import extract_real_ip, is_ip_allowed

def test_1_untrusted_peer_ignore_xff_header():
    real = extract_real_ip(remote_addr="203.0.113.10", x_forwarded_for="127.0.0.1")
    assert real != "127.0.0.1"

def test_2_trusted_proxy_take_rightmost_client_ip():
    real = extract_real_ip(remote_addr="10.0.0.5", x_forwarded_for="203.0.113.99, 10.0.0.5")
    assert real == "203.0.113.99"

def test_3_ipv4_mapped_ipv6_equivalence_allow():
    assert is_ip_allowed("::ffff:192.168.1.10") is True

def test_4_cidr_border_ip_inside_pass():
    assert is_ip_allowed("192.168.1.254") is True

def test_5_cidr_outside_ip_reject():
    assert is_ip_allowed("192.168.2.10") is False

def test_6_ip_compressed_ipv6_normalize_match():
    assert is_ip_allowed("::1") is True

def test_7_xff_comma_injection_extra_ips_not_trusted():
    real = extract_real_ip("10.0.0.1", "1.2.3.4, 127.0.0.1")
    assert real != "127.0.0.1"

def test_8_malformed_ip_string_reject_acl():
    with pytest.raises(ValueError):
        is_ip_allowed("192.168.1.99 garbage‑text")

def test_9_ip_with_leading_zero_octal_bypass_normalize():
    assert is_ip_allowed("0xC0.0xA8.0x01.0x0A") is False

def test_10_empty_xff_fallback_remote_addr():
    real = extract_real_ip("10.0.0.9", "")
    assert real == "10.0.0.9"

def test_11_ipv6_not_in_allow_list_reject():
    assert is_ip_allowed("2001:db8::1") is False

def test_12_127_0_0_1_loopback_allow():
    assert is_ip_allowed("127.0.0.1") is True

def test_13_ip_string_whitespace_trim_normalize():
    assert is_ip_allowed(" 127.0.0.1 ") is True

def test_14_bad_cidr_input_handling_no_crash():
    with pytest.raises(ValueError):
        is_ip_allowed("256.99.99.99")

def test_15_multiple_proxy_chains_rightmost_selection():
    real = extract_real_ip("10.0.0.1", "185.1.1.1, 10.0.0.10, 10.0.0.1")
    assert real == "185.1.1.1"
