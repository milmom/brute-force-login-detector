# Brute-Force Login Detector

This script reads an SSH authentication log, finds the failed login attempts, and counts them per IP address. Any IP whose count meets or exceeds a limit is flagged with an ALERT line showing its number of failed logins. The log file and the limit are given on the command line, so it can be run against any log without editing the code. Missing or invalid input prints a usage or error message instead of crashing.

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

$ python3 detector.py
Usage: python3 detector.py <logfile> <limit>
```

## Limitations

- This file can't handle a log that doesn't use the word 'from' in front of the IP 
- This file doesn't account for time between attempts, meaning that while it is a brute force detector, it may detect failed logins that aren't due to brute forcing
- This file handles a log that uses the word "Failed". If the log doesn't use "Failed" exactly, the file will not find anything.
