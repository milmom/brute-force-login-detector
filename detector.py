import re 
import sys # Project 1: brute-force login detector

def failed_ips(path):
    unsuccessful_logins = []
    with open(path) as f:
        for line in f:
            if 'Failed' in line:
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

def report(path, limit):
    
    try:
        detects = failed_ips(path)
    except FileNotFoundError:
        print("ERROR: log file not found:", path)
        return

    counts = count_by_ip(detects)
    flagged = flag_ips(counts, limit)
    
    for ip in flagged:
        
        print("ALERT:", ip, "had", counts[ip], "failed logins")

    if len(flagged) == 0:
        print("No IPs at or over the limit")

def get_limit(args):
    if len(args) < 3:
        print("Usage: python3 detector.py <logfile> <limit>")
        return 
    try:
        limit = int(args[2])
    except ValueError:
        print("Error: Limit value must be a number")
        return None
    return limit

if __name__ == "__main__":        
    
    num = get_limit(sys.argv)
    if num is not None:
        report(sys.argv[1], num) 
        
    
   

    
    

