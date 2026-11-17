import re 
import sys # Project 1: brute-force login detector
from datetime import datetime

def get_time(line):
    t = line[:15]
    timestamp = "2026 " + t
    time = datetime.strptime(timestamp, "%Y %b %d %H:%M:%S")
    return time

def times_by_ip(path):
    times = {}
                
    with open(path) as f:
        for line in f:
            if 'failed' in line.lower():
                ip = re.search(r"\d+\.\d+\.\d+\.\d+", line)
                if ip is None:
                    print("There is no IP in this line")
                else:
                    t = get_time(line)
                    ip_text = ip.group()
                    if ip_text in times:
                        times[ip_text].append(t)
                    else:
                        times[ip_text] = [t]
    return times

def flag_in_window(times, limit, window):
    flagged = []
    for ip in times:
        ip_times = times[ip]
        for i in range(len(ip_times) - limit + 1):
            first = ip_times[i]
            last = ip_times[i + limit - 1]
            if (last - first).total_seconds() <= window:
                flagged.append(ip)
                break
            
    return flagged   

def failed_ips(path):
    unsuccessful_logins = []
    with open(path) as f:
        for line in f:
            if 'failed' in line.lower():
                ip = re.search(r"\d+\.\d+\.\d+\.\d+", line)
                if ip is None:
                    print("There is no IP in this line")
                else:
                    unsuccessful_logins.append(ip.group())
                
        

    return unsuccessful_logins

def flag_ips(counts, limit):
    detected = []
    for i in counts:
        if counts[i] >= limit:
            detected.append(i)

    return detected

def count_by_ip(ips):
    ip_count = {}
    for ip in ips:
        if ip in ip_count:
            ip_count[ip] += 1
        else:
            ip_count[ip] = 1

    return ip_count

def report(path, limit, window):
    
    try:
        detects = failed_ips(path)
    except FileNotFoundError:
        print("ERROR: log file not found:", path)
        return
    
    if window is None:
        counts = count_by_ip(detects)
        flagged = flag_ips(counts, limit)
        
        if len(flagged) == 0:
            print("No IPs at or over the limit")
            return
        for ip in flagged:
            print("ALERT:", ip, "had", counts[ip], "failed logins")

    else:
        flagged = flag_in_window(times_by_ip(path), limit, window)
        
        if len(flagged) == 0:
                print("No IPs were flagged")
                return
        for ip in flagged:
            print("ALERT:", ip, "had", limit, "or more failed logins within", window, "seconds")

def get_limit(args):
    if len(args) < 3:
        print("Usage: python3 detector.py <logfile> <limit> [window]")
        return 
    try:
        limit = int(args[2])
    except ValueError:
        print("Error: Limit value must be a number")
        return None
    return limit

def get_window(args):
    if len(args) < 4:
        return None
    try:
        window = int(args[3])
    except ValueError:
        print("Error: Window value must be a number")
        return None
    return window


if __name__ == "__main__":        
    
    num = get_limit(sys.argv)
    if num is not None:
        window = get_window(sys.argv)
        report(sys.argv[1], num, window) 
        
    
   

    
    

