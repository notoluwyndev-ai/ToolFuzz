"""Backend execution allowlist. Tool JSON files must match these arguments exactly."""

COMMANDS = {
    "nmap_quick": {
        "binary": "nmap",
        "args": ["-F", "-T4", "{target}"],
        "danger": "recon",
    },
    "nmap_full_ports": {
        "binary": "nmap",
        "args": ["-p-", "-T{timing}", "{target}"],
        "danger": "recon",
    },
    "nmap_version_scripts": {
        "binary": "nmap",
        "args": ["-sV", "-p", "{ports}", "{target}"],
        "danger": "recon",
    },
    "rustscan_private": {
        "binary": "rustscan",
        "args": ["-a", "{target}", "-p", "{ports}", "--", "-sT", "-Pn"],
        "danger": "recon",
    },
    "masscan_private": {
        "binary": "masscan",
        "args": ["-p", "{ports}", "{target}", "--rate", "{rate}"],
        "danger": "active",
    },
    "gobuster_dir": {
        "binary": "gobuster",
        "args": ["dir", "-u", "http://{target}", "-w", "{wordlist}"],
        "danger": "active",
    },
    "whatweb_private": {
        "binary": "ruby",
        "args": ["--no-errors", "{url}"],
        "danger": "recon",
    },
    "arp_table": {
        "binary": "arp",
        "args": ["-a"],
        "danger": "recon",
    },
    "whois_lookup": {
        "binary": "whois",
        "args": ["-accepteula", "{domain}"],
        "danger": "recon",
    },
}