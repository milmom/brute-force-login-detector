from detector import failed_ips, count_by_ip, flag_ips # pytest tests for detector.py
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

