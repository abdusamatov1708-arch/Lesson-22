# Lesson-22
from collections import Counter
import re

MASKING_PATTERN = re.compile(
    r"""
    (
        \d{3}[-.\s]?\d{2}[-.\s]?\d{2}[-.\s]?\d{2} |  # Telefon raqami
        [a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+  # Email
    )
""",
    re.VERBOSE,
)

ERROR_PATTERN = re.compile(
    r"""
    \b(ERROR|WARNING|CRITICAL)\b  # Log darajasi
""",
    re.VERBOSE | re.IGNORECASE,
)

LOG_PATTERN = re.compile(
    r"""
    ^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \s+  # 1. IPv4 manzil
    - \s+ 
    - \s+
    \[(.*?)\] \s+                              # 2. Sana-vaqt belgisi
    "(GET|POST|PUT|DELETE|OPTIONS|HEAD) \s+    # 3. HTTP metod
    (\S+) \s+                                  # 4. URL
    (HTTP/\d\.\d)" \s+                         # Protokol
    (\d{3}) \s+                                # 5. Status code
    (\d+)                                      # Javob hajmi (bayt)
""",
    re.VERBOSE,
)


def analyze_log_file(file_path):
    ip_list = []
    url_list = []
    status_codes = []
    error_logs = []
    masked_lines = []

    with open(file_path, "r", encoding="utf-8") as file:
        log_lines = file.readlines()

    for line in log_lines:
        masked_line = MASKING_PATTERN.sub("[MAXFIY]", line)
        masked_lines.append(masked_line.strip())

        errors = ERROR_PATTERN.findall(line)
        if errors:
            error_logs.append(line.strip())

        match = LOG_PATTERN.search(line)
        if match:
            ip, timestamp, method, url, http_ver, status, size = (
                match.groups()
            )

            ip_list.append(ip)
            url_list.append(f"{method} {url}")
            status_codes.append(status)

    ip_counts = Counter(ip_list)
    url_counts = Counter(url_list)
    status_counts = Counter(status_codes)

    return {
        "total_logs": len(log_lines),
        "unique_ips": len(ip_counts),
        "top_ips": ip_counts.most_common(5),
        "top_urls": url_counts.most_common(5),
        "status_distribution": dict(status_counts),
        "error_count": len(error_logs),
        "error_logs": error_logs[:10],
        "masked_logs": masked_lines[:10],
    }



if __name__ == "__main__":
    sample_log = """
127.0.0.1 - - [20/Jun/2026:12:00:00 +0500] "GET /index.html HTTP/1.1" 200 1024
192.168.1.15 - - [20/Jun/2026:12:05:12 +0500] "POST /api/login HTTP/1.1" 401 512
ERROR Database connection failed for user@domain.com
10.0.0.5 - - [20/Jun/2026:12:10:45 +0500] "GET /contact HTTP/1.1" 200 2048
192.168.1.15 - - [20/Jun/2026:12:15:00 +0500] "GET /dashboard HTTP/1.1" 200 4096
ERROR Server timeout on +998901234567
"""

    with open("server.log", "w") as f:
        f.write(sample_log.strip())

    results = analyze_log_file("server.log")

    print("--- STATISTIKA ---")
    print(f"Jami loglar soni: {results['total_logs']}")
    print(f"Takrorlanmagan IP manzillar: {results['unique_ips']}")
    print(f"Top IP'lar: {results['top_ips']}")
    print(f"Top URL'lar: {results['top_urls']}")
    print(f"Status kodlar taqsimoti: {results['status_distribution']}")

    print("\n--- MAXFIY MA'lumotlarni YASHIRISH (re.sub) ---")
    for log in results["masked_logs"]:
        print(log)

    print(f"\n--- TOPILGAN XATOLAR: {results['error_count']} ta ---")
    for err in results["error_logs"]:
        print(err)
