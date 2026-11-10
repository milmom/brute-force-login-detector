# Brute-Force Login Detector

This script reads an SSH authentication log, finds the failed login attempts, and counts them per IP address. Any IP whose count meets or exceeds a limit is flagged with an ALERT line showing its number of failed logins. The log file and limit are set in the `report()` calls at the bottom of `detector.py` (currently `auth_sample.log` with a limit of 3).

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
ERROR: log file not found: missing.log
```

The second line comes from a deliberate call on a file that doesn't exist, showing that a missing log prints an error instead of crashing.

## Limitations

- This file can't handle a log that doesn't use the word 'from' in front of the IP 
- This file doesn't account for time between attempts, meaning that while it is a brute force detector, it may detect failed logins that aren't due to brute forcing
- This file handles a log that uses the word "Failed". If the log doesn't use "Failed" exactly, the file will not find anything.
