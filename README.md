This file takes a log file containing IP addresses and analyzes how many failed attempts each IP address had.
The user defines the limit, determining whether the IP should be flagged or not.
You can run this the following using these commands: 
git clone
https://github.com/milmom/brute-force-login-detector.git
cd brute-force-login-detector
python3 detector.py

For the tests:
pip install pytest
python3 -m pytest


Expected output: ALERT: 203.0.113.5 had 3 failed logins

Limitations:
If the log's IP doesn't come after the word 'from', this detector is rendered useless.
