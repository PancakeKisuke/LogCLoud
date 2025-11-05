# test_parser.py
import pytest
from datetime import datetime
from app import LogParser # Import only the class we are testing

# --- Tests for LogParser Class ---

# Test 1: Full Statement Coverage for Syslog Format
def test_parser_syslog_full_coverage():
    """Tests syslog parsing, including IP extraction and ERROR severity."""
    # This log hits: syslog regex, IP address regex, and error severity check.
    log = "<166>Oct 26 15:30:01 router1 sshd[1234]: Failed password for admin from 192.168.1.100"
    result = LogParser.parse_log(log)
    
    assert result is not None
    assert result['format'] == 'syslog'
    assert result['ipAddress'] == '192.168.1.100'
    assert result['severity'] == 'error'
    assert 'Failed password' in result['message']

# Test 2: Branch Coverage for Apache/Nginx (Different Status Codes)
def test_parser_apache_nginx_branch_coverage():
    """Tests the status code branches (2xx, 4xx, 5xx) in Apache/Nginx parsing."""
    
    # 5xx Branch (Error, hits status >= 500)
    log_500 = '172.16.0.3 - - [09/Nov/2025:16:53:32 +0000] "POST /api/fail HTTP/1.1" 500 0'
    result_500 = LogParser.parse_log(log_500)
    assert result_500['severity'] == 'error'
    
    # 4xx Branch (Warning, hits status >= 400 and < 500)
    log_404 = '172.16.0.1 - - [09/Nov/2025:16:53:32 +0000] "GET /nonexistent HTTP/1.1" 404 512'
    result_404 = LogParser.parse_log(log_404)
    assert result_404['severity'] == 'warning'
    
    # 2xx/3xx Branch (Info, hits the final 'else' for severity)
    log_200 = '172.16.0.2 - - [09/Nov/2025:16:53:32 +0000] "GET /index.html HTTP/1.1" 200 1024'
    result_200 = LogParser.parse_log(log_200)
    assert result_200['severity'] == 'info'

# Test 3: Firewall and Specific Keyword Branches
def test_parser_firewall_and_critical_keywords():
    """Tests firewall regex and the generic log check for CRITICAL keyword."""
    
    # Firewall regex match branch (iptables pattern)
    log_firewall = "Timestamp: Nov 09 2025, 16:53:32 SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP DPT=22 [BLOCKED]"
    result_firewall = LogParser.parse_log(log_firewall)
    assert result_firewall['format'] == 'firewall'
    assert result_firewall['severity'] == 'warning' # From specific firewall check

    # Generic Fallback & Critical Severity branch (to cover final function lines)
    log_generic_critical = "A generic message with no format but a CRITICAL system failure"
    result_generic = LogParser.parse_log(log_generic_critical)
    assert result_generic['format'] == 'generic'
    assert result_generic['severity'] == 'critical'
    
# Test 4: Timestamp Parsing Branch Coverage
def test_parser_timestamp_branches():
    """Tests multiple timestamp formats to cover internal helper method branches."""
    
    # Format 1 (with year)
    ts1 = LogParser._parse_timestamp("[Nov 09 2025, 16:53:32]")
    assert ts1 is not None and ts1.year == 2025
    
    # Format 3 (no year - uses current year)
    current_year = datetime.now().year
    ts3 = LogParser._parse_timestamp("Oct 26 15:30:01")
    assert ts3 is not None and ts3.year == current_year
    
    # Format 4 (return None branch)
    ts_none = LogParser._parse_timestamp("Invalid Date Format")
    assert ts_none is None