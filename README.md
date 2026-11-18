# Brute-Force Login Detector

This script reads an SSH authentication log, finds the failed login attempts(not case-sensitive), and counts them per IP address. Any IP whose count meets or exceeds a limit is flagged with an ALERT line showing its number of failed logins. Additionally, you can identify a window of time(in seconds), then identify failed login attempts equaling or exceeding the limit. The log file and the limit are given on the command line, so it can be run against any log without editing the code. Missing or invalid input prints a usage or error message instead of crashing. Finds IPv4 addresses anywhere in the line using regex.

## How to run

```
git clone https://github.com/milmom/brute-force-login-detector.git
cd brute-force-login-detector
python3 detector.py <logfile> <limit>
```

Example, using the included sample log:

```
python3 detector.py auth_sample.log 3
```

To run the tests:

```
pip install pytest
python3 -m pytest
```

## Sample output

```
$ python3 detector.py auth_sample.log 3
ALERT: 203.0.113.5 had 3 failed logins

$ python3 detector.py auth_sample.log 2
ALERT: 203.0.113.5 had 3 failed logins
ALERT: 192.0.2.44 had 2 failed logins

$ python3 detector.py missing.log 3
ERROR: log file not found: missing.log

$ python3 detector.py auth_sample.log abc
Error: Limit value must be a number

$ python3 detector.py auth_sample.log 2 10
ALERT: 203.0.113.5 had 2 or more failed logins within 10 seconds
ALERT: 192.0.2.44 had 2 or more failed logins within 10 seconds

$ python3 detector.py
Usage: python3 detector.py <logfile> <limit> [window]
```

## Limitations
-Year is hardcoded(2026), so logs from previous or future logs get wrong dates
-Only IPv4 addresses are found. The regex doesn't find IPv6 addresses
-The script compares positions in a list, relying on the log being written in time order

