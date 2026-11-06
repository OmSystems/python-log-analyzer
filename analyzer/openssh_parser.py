import re
import ipaddress

def parse_openssh_log_line(line):
    match = re.match(
        r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)",
        line,
    )
    if match is not None:
        month = match.group(1)
        date = match.group(2)
        time = match.group(3)
        hostname = match.group(4)
        process_name = match.group(5)
        if process_name != "sshd":
            return None
        pid = match.group(6)
        msg = match.group(7)

        # Match either IPv4 or IPv6 (capturing non-whitespace characters after 'from ')
        ip_match = re.search(r"from\s+(\S+)", msg)
        source_ip = None
        if ip_match:
            candidate_ip = ip_match.group(1)
            try:
                ipaddress.ip_address(candidate_ip)
                source_ip = candidate_ip
            except ValueError:
                source_ip = None
        result = {
            "month": month,
            "date": date,
            "time": time,
            "hostname": hostname,
            "process_name": process_name,
            "pid": pid,
            "message": msg,
            "source_ip": source_ip,
        }
        return result
    else:
        return None