import sys # Project 1: brute-force login detector

def failed_ips(path):
    unsuccessful_logins = []
    with open(path) as f:
        for line in f:
            if "Failed" in line:
                w = line.split()
                unsuccessful_logins.append(w[w.index("from") + 1])

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
        
if __name__ == "__main__":        
    CL_input = sys.argv
    
    if len(CL_input) < 3:
        print("Usage: python3 detector.py", sys.argv[0], sys.argv[1])
    
    try:
        num = int(CL_input[2])
    except ValueError:
        print("Error: Limit value must be a number")
        
    
   

    
    report(CL_input[1], CL_input[2]) 
    report(CL_input[1], CL_input[2])

