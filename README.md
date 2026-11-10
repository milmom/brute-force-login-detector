# Brute-Force Login Detector

This file reads an authentication log and counts how many IPs failed to log in. It then flags these IPs with the number of failed logins if the count meets or exceeds the target number of failures.

## How to run

```
git clone https://github.com/milmom/brute-force-login-detector.git
cd brute-force-login-detector
python3 detector.py
```

To run the tests:

```
pip install pytest
python3 -m pytest
```

## Sample output

```
ALERT: 203.0.113.5 had 3 failed logins
ALERT: 192.0.2.44 had 2 failed logins
```

ALERT: 203.0.113.5 had 3 failed logins
ERROR: log file not found: missing.log

## Limitations

- This file can't handle a log that doesn't use the word 'from' in front of the IP 
- This file doesn't account for time between attempts, meaning that while it is a brute force detector, it may detect failed logins that aren't due to brute forcing
- This file handles a log that uses the word "Failed". If the log doesn't use "Failed" exactly, the file will not find anything.
