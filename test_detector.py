from datetime import datetime
from detector import failed_ips, count_by_ip, flag_ips, get_limit, get_time, times_by_ip, flag_in_window, get_window # pytest tests for detector.py
#flag_ips with nothing flagged, and failed_ips("auth_sample.log"). (Note: importing detector runs its bottom lines too, so the report output will also print. 

def test_count_by_ip_empty():
    assert count_by_ip([]) == {}

def test_count_by_ip_repeats():
    assert count_by_ip(["10.0.0.1", "10.0.0.1",]) == {'10.0.0.1': 2}

def test_flag_ips_equal_limit():
    assert flag_ips({'10.0.0.1': 2}, 2) == ["10.0.0.1"]

def test_flag_ips_nothing():
    assert flag_ips({'10.0.0.1': 2}, 4) == []

def test_failed_ips_from_sample_log():
    assert failed_ips("auth_sample.log") == ["203.0.113.5", "203.0.113.5", "192.0.2.44", "192.0.2.44", "203.0.113.5", "198.51.100.23"]

def test_get_limit_one_input():
    assert get_limit(["detector.py"]) == None

def test_get_limit_two_inputs():
    assert get_limit(["detector.py", "auth_sample.log"]) == None

def test_get_limit_string_limit_input():
    assert get_limit(["detector.py", "auth_sample.log", "abc"]) == None

def test_get_limit_pass():
    assert get_limit(["detector.py", "auth_sample.log", "3"]) == 3

def test_failed_ips_on_no_from_log():
    assert failed_ips("auth_no_from.log") == ['203.0.113.9', '203.0.113.9']

def test_failed_ips_on_mixed_case_log():
    assert failed_ips("auth_mixed_case.log") == ['203.0.113.77', '203.0.113.77']

def test_get_time_on_auth_sample_log():
    assert get_time("Nov  6 09:12:01 web1 sshd[1201]: Failed password for root from 203.0.113.5 port 52113 ssh2") == datetime(2026, 11, 6, 9, 12, 1)

def test_times_by_ip_on_auth_sample_log():
    assert times_by_ip("auth_sample.log")['192.0.2.44'] == [datetime(2026, 11, 6, 9, 14, 22), datetime(2026, 11, 6, 9, 14, 25)]

def test_flag_in_window_on_auth_sample_log():
    assert flag_in_window(times_by_ip("auth_sample.log"), 2, 10) == ['203.0.113.5', '192.0.2.44']

def test_flag_in_window_on_auth_sample_log_empty_list_return():
    assert flag_in_window(times_by_ip("auth_sample.log"), 3, 60) == []

def test_get_window_no_window():
    assert get_window(["detector.py", "auth_sample.log", "3"]) == None

def test_get_window_string_window():
    assert get_window(["detector.py", "auth_sample.log", "3", "abc"]) == None

def test_get_window_int_window():
    assert get_window(["detector.py", "auth_sample.log", "3", "10"]) == 10
