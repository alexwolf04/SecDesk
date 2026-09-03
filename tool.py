#!/usr/bin/env python3

import os
import shlex
import shutil
import subprocess
import threading
import queue
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


# ============================================================
# SecDesk
# Enterprise-style Cybersecurity Toolkit
# Designed for authorized security testing, labs, and auditing
# ============================================================


APP_NAME = "SecDesk"
VERSION = "2.0"

WORKSPACE = Path.home() / "SecDesk"
REPORTS = WORKSPACE / "reports"
WORKSPACE.mkdir(exist_ok=True)
REPORTS.mkdir(exist_ok=True)


# ============================================================
# TOOL DEFINITIONS
# ============================================================

TOOLS = {

    "Network": {

        "Nmap": {
            "binary": "nmap",
            "description": "Finds hosts, open ports, services, versions, and operating systems.",
            "operations": {

                "Host Discovery": {
                    "description": "Find live hosts without performing a normal port scan.",
                    "fields": [
                        ("target", "Target / Network", "text", True),
                    ],
                    "command": lambda v: ["nmap", "-sn", v["target"]]
                },

                "Basic Port Scan": {
                    "description": "Checks the most common TCP ports on a target.",
                    "fields": [
                        ("target", "Target", "text", True),
                    ],
                    "command": lambda v: ["nmap", v["target"]]
                },

                "Service Detection": {
                    "description": "Attempts to identify services and their versions.",
                    "fields": [
                        ("target", "Target", "text", True),
                    ],
                    "command": lambda v: ["nmap", "-sV", v["target"]]
                },

                "OS Detection": {
                    "description": "Attempts to identify the operating system.",
                    "fields": [
                        ("target", "Target", "text", True),
                    ],
                    "command": lambda v: ["nmap", "-O", v["target"]]
                },

                "Full TCP Scan": {
                    "description": "Checks all 65,535 TCP ports.",
                    "fields": [
                        ("target", "Target", "text", True),
                    ],
                    "command": lambda v: ["nmap", "-p-", v["target"]]
                },

                "UDP Top Ports": {
                    "description": "Checks the most common UDP ports.",
                    "fields": [
                        ("target", "Target", "text", True),
                        ("ports", "Number of Ports", "text", False, "100"),
                    ],
                    "command": lambda v: [
                        "nmap", "-sU",
                        "--top-ports", v["ports"],
                        v["target"]
                    ]
                },

                "Specific Ports": {
                    "description": "Scan only the ports you specify.",
                    "fields": [
                        ("target", "Target", "text", True),
                        ("ports", "Ports", "text", True, "22,80,443"),
                    ],
                    "command": lambda v: [
                        "nmap", "-p", v["ports"], v["target"]
                    ]
                },

                "Save Service Scan": {
                    "description": "Runs service detection and saves the results to a report.",
                    "fields": [
                        ("target", "Target", "text", True),
                        ("output", "Output File", "file_save", True),
                    ],
                    "command": lambda v: [
                        "nmap", "-sV",
                        "-oN", v["output"],
                        v["target"]
                    ]
                },
            }
        },

        "Masscan": {
            "binary": "masscan",
            "description": "Very fast TCP port scanner designed for large networks.",
            "operations": {

                "Common Ports": {
                    "description": "Scan common TCP ports on a target.",
                    "fields": [
                        ("target", "Target", "text", True),
                        ("ports", "Ports", "text", True, "22,80,443"),
                    ],
                    "command": lambda v: [
                        "masscan", v["target"],
                        "-p", v["ports"]
                    ]
                },

                "Help": {
                    "description": "Display Masscan's built-in help.",
                    "fields": [],
                    "command": lambda v: ["masscan", "--help"]
                }
            }
        },

        "RustScan": {
            "binary": "rustscan",
            "description": "Fast port scanner that can feed discovered ports into other tools.",
            "operations": {

                "Basic Scan": {
                    "description": "Quickly identify open ports.",
                    "fields": [
                        ("target", "Target", "text", True),
                    ],
                    "command": lambda v: [
                        "rustscan", "-a", v["target"]
                    ]
                },

                "Specific Ports": {
                    "description": "Check a selected set of ports.",
                    "fields": [
                        ("target", "Target", "text", True),
                        ("ports", "Ports", "text", True, "22,80,443"),
                    ],
                    "command": lambda v: [
                        "rustscan",
                        "-a", v["target"],
                        "-p", v["ports"]
                    ]
                }
            }
        },

        "Wireshark": {
            "binary": "wireshark",
            "description": "Graphical network protocol analyzer.",
            "operations": {

                "Launch Wireshark": {
                    "description": "Open the Wireshark graphical interface.",
                    "fields": [],
                    "command": lambda v: ["wireshark"],
                    "gui": True
                },

                "Open Capture": {
                    "description": "Open an existing packet capture.",
                    "fields": [
                        ("file", "Capture File", "file", True),
                    ],
                    "command": lambda v: ["wireshark", v["file"]],
                    "gui": True
                }
            }
        },

        "TShark": {
            "binary": "tshark",
            "description": "Command-line version of Wireshark.",
            "operations": {

                "List Interfaces": {
                    "description": "Show available capture interfaces.",
                    "fields": [],
                    "command": lambda v: ["tshark", "-D"]
                },

                "Read Capture": {
                    "description": "Read packets from a capture file.",
                    "fields": [
                        ("file", "Capture File", "file", True),
                    ],
                    "command": lambda v: ["tshark", "-r", v["file"]]
                },

                "Display Filter": {
                    "description": "Read a capture using a Wireshark display filter.",
                    "fields": [
                        ("file", "Capture File", "file", True),
                        ("filter", "Display Filter", "text", True, "http"),
                    ],
                    "command": lambda v: [
                        "tshark",
                        "-r", v["file"],
                        "-Y", v["filter"]
                    ]
                }
            }
        },

        "TCPDump": {
            "binary": "tcpdump",
            "description": "Command-line packet capture and analysis tool.",
            "operations": {

                "List Interfaces": {
                    "description": "Show interfaces available for packet capture.",
                    "fields": [],
                    "command": lambda v: ["tcpdump", "-D"]
                },

                "Read Capture": {
                    "description": "Read packets from a capture file.",
                    "fields": [
                        ("file", "Capture File", "file", True),
                    ],
                    "command": lambda v: ["tcpdump", "-r", v["file"]]
                },

                "Help": {
                    "description": "Display tcpdump help.",
                    "fields": [],
                    "command": lambda v: ["tcpdump", "--help"]
                }
            }
        },

        "Netcat": {
            "binary": "nc",
            "description": "General-purpose network connection and troubleshooting utility.",
            "operations": {

                "Help": {
                    "description": "Display Netcat help.",
                    "fields": [],
                    "command": lambda v: ["nc", "--help"]
                },

                "Test TCP Port": {
                    "description": "Check whether a TCP port accepts a connection.",
                    "fields": [
                        ("target", "Target", "text", True),
                        ("port", "Port", "text", True, "443"),
                    ],
                    "command": lambda v: [
                        "nc", "-vz",
                        v["target"],
                        v["port"]
                    ]
                }
            }
        },

        "Socat": {
            "binary": "socat",
            "description": "Advanced network relay and connection utility.",
            "operations": {

                "Help": {
                    "description": "Display Socat help.",
                    "fields": [],
                    "command": lambda v: ["socat", "-h"]
                }
            }
        },

        "ARP Scan": {
            "binary": "arp-scan",
            "description": "Discovers systems on local Ethernet networks using ARP.",
            "operations": {

                "Local Network": {
                    "description": "Discover systems on the local network.",
                    "fields": [],
                    "command": lambda v: ["arp-scan", "--localnet"]
                },

                "Help": {
                    "description": "Display arp-scan help.",
                    "fields": [],
                    "command": lambda v: ["arp-scan", "--help"]
                }
            }
        },

        "Aircrack-ng": {
            "binary": "aircrack-ng",
            "description": "Wireless security auditing suite.",
            "operations": {

                "Capture Information": {
                    "description": "Display information about a wireless capture.",
                    "fields": [
                        ("file", "Capture File", "file", True),
                    ],
                    "command": lambda v: ["aircrack-ng", v["file"]]
                },

                "Help": {
                    "description": "Display Aircrack-ng help.",
                    "fields": [],
                    "command": lambda v: ["aircrack-ng", "--help"]
                }
            }
        },
    },


    # ========================================================
    # WEB
    # ========================================================

    "Web": {

        "FFUF": {
            "binary": "ffuf",
            "description": "Fast web fuzzing tool for directories, files, parameters, and virtual hosts.",
            "operations": {

                "Directory Discovery": {
                    "description": "Look for hidden directories and endpoints.",
                    "fields": [
                        ("url", "Base URL", "text", True, "https://example.com"),
                        ("wordlist", "Wordlist", "file", True),
                    ],
                    "command": lambda v: [
                        "ffuf",
                        "-u", v["url"].rstrip("/") + "/FUZZ",
                        "-w", v["wordlist"]
                    ]
                },

                "Parameter Fuzzing": {
                    "description": "Test a URL parameter using a wordlist.",
                    "fields": [
                        ("url", "URL", "text", True),
                        ("parameter", "Parameter", "text", True, "id"),
                        ("wordlist", "Wordlist", "file", True),
                    ],
                    "command": lambda v: [
                        "ffuf",
                        "-u",
                        f'{v["url"]}?{v["parameter"]}=FUZZ',
                        "-w", v["wordlist"]
                    ]
                },

                "Virtual Host Discovery": {
                    "description": "Test possible virtual host names.",
                    "fields": [
                        ("url", "Base URL", "text", True),
                        ("domain", "Domain", "text", True, "example.com"),
                        ("wordlist", "Wordlist", "file", True),
                    ],
                    "command": lambda v: [
                        "ffuf",
                        "-u", v["url"],
                        "-H", f'Host: FUZZ.{v["domain"]}',
                        "-w", v["wordlist"]
                    ]
                },

                "Help": {
                    "description": "Display FFUF help.",
                    "fields": [],
                    "command": lambda v: ["ffuf", "-h"]
                }
            }
        },

        "Gobuster": {
            "binary": "gobuster",
            "description": "Directory, DNS, and virtual host enumeration tool.",
            "operations": {

                "Directory Discovery": {
                    "description": "Find directories and files on a web server.",
                    "fields": [
                        ("url", "URL", "text", True),
                        ("wordlist", "Wordlist", "file", True),
                    ],
                    "command": lambda v: [
                        "gobuster", "dir",
                        "-u", v["url"],
                        "-w", v["wordlist"]
                    ]
                },

                "DNS Enumeration": {
                    "description": "Look for DNS subdomains.",
                    "fields": [
                        ("domain", "Domain", "text", True),
                        ("wordlist", "Wordlist", "file", True),
                    ],
                    "command": lambda v: [
                        "gobuster", "dns",
                        "-d", v["domain"],
                        "-w", v["wordlist"]
                    ]
                },

                "Virtual Host Discovery": {
                    "description": "Look for virtual hosts.",
                    "fields": [
                        ("url", "URL", "text", True),
                        ("wordlist", "Wordlist", "file", True),
                    ],
                    "command": lambda v: [
                        "gobuster", "vhost",
                        "-u", v["url"],
                        "-w", v["wordlist"]
                    ]
                }
            }
        },

        "Feroxbuster": {
            "binary": "feroxbuster",
            "description": "Fast recursive content discovery tool.",
            "operations": {

                "Directory Discovery": {
                    "description": "Search a web application for directories and files.",
                    "fields": [
                        ("url", "URL", "text", True),
                        ("wordlist", "Wordlist", "file", False),
                    ],
                    "command": lambda v: (
                        ["feroxbuster", "-u", v["url"]]
                        + (["-w", v["wordlist"]] if v.get("wordlist") else [])
                    )
                }
            }
        },

        "Nikto": {
            "binary": "nikto",
            "description": "Web server scanner that checks for common issues and misconfigurations.",
            "operations": {

                "Web Server Scan": {
                    "description": "Run a standard Nikto scan against a web server.",
                    "fields": [
                        ("url", "URL", "text", True),
                    ],
                    "command": lambda v: [
                        "nikto", "-h", v["url"]
                    ]
                }
            }
        },

        "SQLMap": {
            "binary": "sqlmap",
            "description": "Automates SQL injection testing and database enumeration.",
            "operations": {

                "Test URL": {
                    "description": "Test a URL for SQL injection vulnerabilities.",
                    "fields": [
                        ("url", "URL", "text", True),
                    ],
                    "command": lambda v: [
                        "sqlmap", "-u", v["url"], "--batch"
                    ]
                },

                "List Databases": {
                    "description": "Enumerate databases after an authorized SQL injection test.",
                    "fields": [
                        ("url", "URL", "text", True),
                    ],
                    "command": lambda v: [
                        "sqlmap", "-u", v["url"],
                        "--dbs", "--batch"
                    ]
                },

                "List Tables": {
                    "description": "List tables in a selected database.",
                    "fields": [
                        ("url", "URL", "text", True),
                        ("database", "Database", "text", True),
                    ],
                    "command": lambda v: [
                        "sqlmap", "-u", v["url"],
                        "-D", v["database"],
                        "--tables", "--batch"
                    ]
                }
            }
        },

        "WPScan": {
            "binary": "wpscan",
            "description": "WordPress security scanner.",
            "operations": {

                "Basic Scan": {
                    "description": "Scan a WordPress installation.",
                    "fields": [
                        ("url", "WordPress URL", "text", True),
                    ],
                    "command": lambda v: [
                        "wpscan", "--url", v["url"]
                    ]
                },

                "Enumerate Plugins and Users": {
                    "description": "Look for WordPress plugins and user information.",
                    "fields": [
                        ("url", "WordPress URL", "text", True),
                    ],
                    "command": lambda v: [
                        "wpscan",
                        "--url", v["url"],
                        "--enumerate", "p,u"
                    ]
                }
            }
        },

        "WhatWeb": {
            "binary": "whatweb",
            "description": "Identifies web technologies, frameworks, servers, and applications.",
            "operations": {

                "Technology Scan": {
                    "description": "Identify technologies used by a website.",
                    "fields": [
                        ("url", "URL", "text", True),
                    ],
                    "command": lambda v: [
                        "whatweb", v["url"]
                    ]
                }
            }
        },

        "Nuclei": {
            "binary": "nuclei",
            "description": "Template-based vulnerability scanner.",
            "operations": {

                "Scan URL": {
                    "description": "Run the default vulnerability templates against a URL.",
                    "fields": [
                        ("url", "URL", "text", True),
                    ],
                    "command": lambda v: [
                        "nuclei", "-u", v["url"]
                    ]
                },

                "Severity Scan": {
                    "description": "Only run templates matching selected severity levels.",
                    "fields": [
                        ("url", "URL", "text", True),
                        ("severity", "Severity", "combo", True,
                         ["info", "low", "medium", "high", "critical"]),
                    ],
                    "command": lambda v: [
                        "nuclei",
                        "-u", v["url"],
                        "-severity", v["severity"]
                    ]
                },

                "Scan URL List": {
                    "description": "Scan multiple URLs from a text file.",
                    "fields": [
                        ("file", "URL List", "file", True),
                    ],
                    "command": lambda v: [
                        "nuclei", "-l", v["file"]
                    ]
                },

                "Save Results": {
                    "description": "Run a scan and save the results.",
                    "fields": [
                        ("url", "URL", "text", True),
                        ("output", "Output File", "file_save", True),
                    ],
                    "command": lambda v: [
                        "nuclei",
                        "-u", v["url"],
                        "-o", v["output"]
                    ]
                }
            }
        },

        "HTTPX": {
            "binary": "httpx",
            "description": "HTTP probing and web service discovery tool.",
            "operations": {

                "Probe URL": {
                    "description": "Check a web endpoint and report HTTP information.",
                    "fields": [
                        ("url", "URL", "text", True),
                    ],
                    "command": lambda v: [
                        "httpx", "-u", v["url"]
                    ]
                },

                "Probe URL List": {
                    "description": "Probe multiple URLs from a file.",
                    "fields": [
                        ("file", "URL List", "file", True),
                    ],
                    "command": lambda v: [
                        "httpx", "-l", v["file"]
                    ]
                }
            }
        },

        "Katana": {
            "binary": "katana",
            "description": "Fast web crawler for discovering URLs and endpoints.",
            "operations": {

                "Crawl Website": {
                    "description": "Crawl a website and discover URLs.",
                    "fields": [
                        ("url", "URL", "text", True),
                    ],
                    "command": lambda v: [
                        "katana", "-u", v["url"]
                    ]
                },

                "Crawl URL List": {
                    "description": "Crawl multiple targets from a file.",
                    "fields": [
                        ("file", "URL List", "file", True),
                    ],
                    "command": lambda v: [
                        "katana", "-list", v["file"]
                    ]
                }
            }
        }
    },


    # ========================================================
    # RECON
    # ========================================================

    "Recon": {

        "Amass": {
            "binary": "amass",
            "description": "Attack surface mapping and DNS enumeration framework.",
            "operations": {

                "Domain Enumeration": {
                    "description": "Enumerate subdomains and related infrastructure.",
                    "fields": [
                        ("domain", "Domain", "text", True),
                    ],
                    "command": lambda v: [
                        "amass", "enum", "-d", v["domain"]
                    ]
                }
            }
        },

        "Subfinder": {
            "binary": "subfinder",
            "description": "Passive subdomain discovery tool.",
            "operations": {

                "Find Subdomains": {
                    "description": "Discover subdomains from passive sources.",
                    "fields": [
                        ("domain", "Domain", "text", True),
                    ],
                    "command": lambda v: [
                        "subfinder", "-d", v["domain"]
                    ]
                }
            }
        },

        "Assetfinder": {
            "binary": "assetfinder",
            "description": "Find domains and subdomains associated with an organization.",
            "operations": {

                "Find Assets": {
                    "description": "Search for known domain assets.",
                    "fields": [
                        ("domain", "Domain", "text", True),
                    ],
                    "command": lambda v: [
                        "assetfinder", v["domain"]
                    ]
                }
            }
        },

        "Naabu": {
            "binary": "naabu",
            "description": "Fast port scanner designed for attack surface discovery.",
            "operations": {

                "Port Scan": {
                    "description": "Discover open ports on a target.",
                    "fields": [
                        ("target", "Target", "text", True),
                    ],
                    "command": lambda v: [
                        "naabu", "-host", v["target"]
                    ]
                }
            }
        },

        "DNSRecon": {
            "binary": "dnsrecon",
            "description": "DNS enumeration and reconnaissance tool.",
            "operations": {

                "DNS Enumeration": {
                    "description": "Perform DNS reconnaissance against a domain.",
                    "fields": [
                        ("domain", "Domain", "text", True),
                    ],
                    "command": lambda v: [
                        "dnsrecon", "-d", v["domain"]
                    ]
                }
            }
        },

        "DNSEnum": {
            "binary": "dnsenum",
            "description": "DNS information gathering tool.",
            "operations": {

                "Domain Enumeration": {
                    "description": "Enumerate DNS records and related information.",
                    "fields": [
                        ("domain", "Domain", "text", True),
                    ],
                    "command": lambda v: [
                        "dnsenum", v["domain"]
                    ]
                }
            }
        },

        "theHarvester": {
            "binary": "theHarvester",
            "description": "OSINT tool for gathering publicly available information about domains.",
            "operations": {

                "Domain OSINT": {
                    "description": "Gather publicly available domain information.",
                    "fields": [
                        ("domain", "Domain", "text", True),
                    ],
                    "command": lambda v: [
                        "theHarvester",
                        "-d", v["domain"],
                        "-b", "all"
                    ]
                }
            }
        },

        "WHOIS": {
            "binary": "whois",
            "description": "Queries domain registration and ownership information.",
            "operations": {

                "Lookup Domain": {
                    "description": "Query WHOIS information for a domain.",
                    "fields": [
                        ("domain", "Domain", "text", True),
                    ],
                    "command": lambda v: [
                        "whois", v["domain"]
                    ]
                }
            }
        }
    },


    # ========================================================
    # ACTIVE DIRECTORY
    # ========================================================

    "Active Directory": {

        "NetExec": {
            "binary": "nxc",
            "description": "Network service enumeration and security auditing framework.",
            "operations": {

                "SMB Enumeration": {
                    "description": "Enumerate SMB information from an authorized system.",
                    "fields": [
                        ("target", "Target", "text", True),
                    ],
                    "command": lambda v: [
                        "nxc", "smb", v["target"]
                    ]
                },

                "SMB Shares": {
                    "description": "List accessible SMB shares.",
                    "fields": [
                        ("target", "Target", "text", True),
                    ],
                    "command": lambda v: [
                        "nxc", "smb", v["target"],
                        "--shares"
                    ]
                },

                "LDAP Enumeration": {
                    "description": "Query basic LDAP information from an authorized directory.",
                    "fields": [
                        ("target", "Domain Controller", "text", True),
                    ],
                    "command": lambda v: [
                        "nxc", "ldap", v["target"]
                    ]
                }
            }
        },

        "Impacket": {
            "binary": "impacket-smbclient",
            "description": "Python toolkit for Windows network protocol testing and Active Directory security work.",
            "operations": {

                "SMB Client Help": {
                    "description": "Display Impacket SMB client help.",
                    "fields": [],
                    "command": lambda v: [
                        "impacket-smbclient", "-h"
                    ]
                }
            }
        },

        "Certipy": {
            "binary": "certipy",
            "description": "Active Directory Certificate Services auditing and assessment tool.",
            "operations": {

                "Find AD CS Configuration": {
                    "description": "Enumerate certificate services configuration during an authorized assessment.",
                    "fields": [
                        ("user", "Username", "text", True),
                        ("password", "Password", "text", True),
                        ("dcip", "Domain Controller IP", "text", True),
                    ],
                    "command": lambda v: [
                        "certipy", "find",
                        "-u", v["user"],
                        "-p", v["password"],
                        "-dc-ip", v["dcip"]
                    ]
                },

                "Help": {
                    "description": "Display Certipy help.",
                    "fields": [],
                    "command": lambda v: ["certipy", "-h"]
                }
            }
        },

        "LDAPSearch": {
            "binary": "ldapsearch",
            "description": "Command-line LDAP query utility.",
            "operations": {

                "Help": {
                    "description": "Display LDAPSearch help.",
                    "fields": [],
                    "command": lambda v: ["ldapsearch", "-h"]
                }
            }
        },

        "SMBClient": {
            "binary": "smbclient",
            "description": "Command-line SMB/CIFS client.",
            "operations": {

                "List Shares": {
                    "description": "Query available SMB shares.",
                    "fields": [
                        ("target", "Target", "text", True),
                    ],
                    "command": lambda v: [
                        "smbclient", "-L", v["target"]
                    ]
                }
            }
        },

        "RPCClient": {
            "binary": "rpcclient",
            "description": "RPC client used for Windows/SMB security testing.",
            "operations": {

                "Help": {
                    "description": "Display rpcclient help.",
                    "fields": [],
                    "command": lambda v: ["rpcclient", "-h"]
                }
            }
        }
    },


    # ========================================================
    # CREDENTIAL / PASSWORD AUDITING
    # ========================================================

    "Credentials": {

        "Hashcat": {
            "binary": "hashcat",
            "description": "High-performance password hash auditing tool.",
            "operations": {

                "Dictionary Audit": {
                    "description": "Audit an authorized hash file against a wordlist.",
                    "fields": [
                        ("mode", "Hash Mode", "text", True, "0"),
                        ("hashfile", "Hash File", "file", True),
                        ("wordlist", "Wordlist", "file", True),
                    ],
                    "command": lambda v: [
                        "hashcat",
                        "-m", v["mode"],
                        v["hashfile"],
                        v["wordlist"]
                    ]
                },

                "Show Recovered": {
                    "description": "Display hashes that Hashcat has already recovered.",
                    "fields": [
                        ("mode", "Hash Mode", "text", True),
                        ("hashfile", "Hash File", "file", True),
                    ],
                    "command": lambda v: [
                        "hashcat",
                        "-m", v["mode"],
                        v["hashfile"],
                        "--show"
                    ]
                },

                "Identify Hash": {
                    "description": "Display Hashcat information and supported hash modes.",
                    "fields": [],
                    "command": lambda v: ["hashcat", "--help"]
                }
            }
        },

        "John the Ripper": {
            "binary": "john",
            "description": "Password auditing and recovery tool.",
            "operations": {

                "Dictionary Audit": {
                    "description": "Audit an authorized password hash file with a wordlist.",
                    "fields": [
                        ("hashfile", "Hash File", "file", True),
                        ("wordlist", "Wordlist", "file", True),
                    ],
                    "command": lambda v: [
                        "john",
                        f"--wordlist={v['wordlist']}",
                        v["hashfile"]
                    ]
                },

                "Show Recovered": {
                    "description": "Display passwords John has already recovered.",
                    "fields": [
                        ("hashfile", "Hash File", "file", True),
                    ],
                    "command": lambda v: [
                        "john", "--show", v["hashfile"]
                    ]
                }
            }
        },

        "Hydra": {
            "binary": "hydra",
            "description": "Network authentication auditing tool.",
            "operations": {

                "Help": {
                    "description": "Display Hydra help and supported modules.",
                    "fields": [],
                    "command": lambda v: ["hydra", "-h"]
                }
            }
        },

        "Medusa": {
            "binary": "medusa",
            "description": "Parallel network authentication auditing tool.",
            "operations": {

                "Help": {
                    "description": "Display Medusa help.",
                    "fields": [],
                    "command": lambda v: ["medusa", "-h"]
                }
            }
        },

        "Crunch": {
            "binary": "crunch",
            "description": "Wordlist generation utility.",
            "operations": {

                "Generate Wordlist": {
                    "description": "Generate a wordlist with the selected length and character set.",
                    "fields": [
                        ("min", "Minimum Length", "text", True, "4"),
                        ("max", "Maximum Length", "text", True, "6"),
                        ("charset", "Character Set", "text", True, "abcdefghijklmnopqrstuvwxyz"),
                        ("output", "Output File", "file_save", True),
                    ],
                    "command": lambda v: [
                        "crunch",
                        v["min"],
                        v["max"],
                        v["charset"],
                        "-o", v["output"]
                    ]
                }
            }
        }
    },


    # ========================================================
    # EXPLOITATION / FRAMEWORKS
    # ========================================================

    "Exploitation": {

        "Metasploit": {
            "binary": "msfconsole",
            "description": "Penetration testing framework containing modules for authorized security assessments.",
            "operations": {

                "Launch Metasploit": {
                    "description": "Open an interactive Metasploit console.",
                    "fields": [],
                    "command": lambda v: ["msfconsole"],
                    "interactive": True
                },

                "Help": {
                    "description": "Display Metasploit console help.",
                    "fields": [],
                    "command": lambda v: ["msfconsole", "-h"]
                }
            }
        },

        "SearchSploit": {
            "binary": "searchsploit",
            "description": "Command-line interface for searching the Exploit Database.",
            "operations": {

                "Search Exploits": {
                    "description": "Search the local Exploit Database index.",
                    "fields": [
                        ("query", "Search Query", "text", True, "apache 2.4"),
                    ],
                    "command": lambda v: [
                        "searchsploit", v["query"]
                    ]
                },

                "Update Database": {
                    "description": "Update the local Exploit Database index.",
                    "fields": [],
                    "command": lambda v: ["searchsploit", "-u"]
                }
            }
        }
    },


    # ========================================================
    # REVERSE ENGINEERING
    # ========================================================

    "Reverse Engineering": {

        "GDB": {
            "binary": "gdb",
            "description": "GNU debugger for analyzing and debugging programs.",
            "operations": {

                "Open Binary": {
                    "description": "Open a binary in GDB.",
                    "fields": [
                        ("file", "Binary", "file", True),
                    ],
                    "command": lambda v: ["gdb", v["file"]],
                    "interactive": True
                }
            }
        },

        "LLDB": {
            "binary": "lldb",
            "description": "LLVM debugger.",
            "operations": {

                "Open Binary": {
                    "description": "Open a binary in LLDB.",
                    "fields": [
                        ("file", "Binary", "file", True),
                    ],
                    "command": lambda v: ["lldb", v["file"]],
                    "interactive": True
                }
            }
        },

        "Radare2": {
            "binary": "radare2",
            "description": "Command-line reverse engineering and binary analysis framework.",
            "operations": {

                "Open Binary": {
                    "description": "Open a binary for analysis.",
                    "fields": [
                        ("file", "Binary", "file", True),
                    ],
                    "command": lambda v: ["radare2", v["file"]],
                    "interactive": True
                }
            }
        },

        "Ghidra": {
            "binary": "ghidra",
            "description": "Graphical reverse engineering framework.",
            "operations": {

                "Launch Ghidra": {
                    "description": "Open the Ghidra graphical interface.",
                    "fields": [],
                    "command": lambda v: ["ghidra"],
                    "gui": True
                }
            }
        },

        "Strings": {
            "binary": "strings",
            "description": "Extract printable strings from binary files.",
            "operations": {

                "Extract Strings": {
                    "description": "Display printable strings found in a file.",
                    "fields": [
                        ("file", "File", "file", True),
                    ],
                    "command": lambda v: ["strings", v["file"]]
                }
            }
        },

        "Objdump": {
            "binary": "objdump",
            "description": "Display information from object and executable files.",
            "operations": {

                "Disassemble": {
                    "description": "Disassemble executable code.",
                    "fields": [
                        ("file", "Binary", "file", True),
                    ],
                    "command": lambda v: [
                        "objdump", "-d", v["file"]
                    ]
                },

                "Headers": {
                    "description": "Display binary headers.",
                    "fields": [
                        ("file", "Binary", "file", True),
                    ],
                    "command": lambda v: [
                        "objdump", "-x", v["file"]
                    ]
                }
            }
        },

        "ReadELF": {
            "binary": "readelf",
            "description": "Inspect ELF executable structure.",
            "operations": {

                "ELF Headers": {
                    "description": "Display ELF header information.",
                    "fields": [
                        ("file", "ELF Binary", "file", True),
                    ],
                    "command": lambda v: [
                        "readelf", "-h", v["file"]
                    ]
                },

                "Program Headers": {
                    "description": "Display ELF program headers.",
                    "fields": [
                        ("file", "ELF Binary", "file", True),
                    ],
                    "command": lambda v: [
                        "readelf", "-l", v["file"]
                    ]
                }
            }
        },

        "Checksec": {
            "binary": "checksec",
            "description": "Checks executable security protections such as PIE, NX, RELRO, and canaries.",
            "operations": {

                "Analyze Binary": {
                    "description": "Display security protections enabled on a binary.",
                    "fields": [
                        ("file", "Binary", "file", True),
                    ],
                    "command": lambda v: [
                        "checksec", "--file=" + v["file"]
                    ]
                }
            }
        },

        "Valgrind": {
            "binary": "valgrind",
            "description": "Dynamic analysis framework for debugging memory problems.",
            "operations": {

                "Memory Check": {
                    "description": "Run a program under Valgrind's memory checker.",
                    "fields": [
                        ("file", "Program", "file", True),
                    ],
                    "command": lambda v: [
                        "valgrind", v["file"]
                    ]
                }
            }
        },

        "QEMU": {
            "binary": "qemu-system-x86_64",
            "description": "Virtual machine emulator useful for malware analysis and isolated labs.",
            "operations": {

                "Help": {
                    "description": "Display QEMU help.",
                    "fields": [],
                    "command": lambda v: [
                        "qemu-system-x86_64", "--help"
                    ]
                }
            }
        }
    },


    # ========================================================
    # DEFENSIVE / BLUE TEAM
    # ========================================================

    "Defensive": {

        "YARA": {
            "binary": "yara",
            "description": "Pattern matching tool commonly used for malware detection and threat hunting.",
            "operations": {

                "Scan File": {
                    "description": "Run YARA rules against a file.",
                    "fields": [
                        ("rule", "YARA Rule File", "file", True),
                        ("file", "Target File", "file", True),
                    ],
                    "command": lambda v: [
                        "yara", v["rule"], v["file"]
                    ]
                },

                "Recursive Scan": {
                    "description": "Run YARA rules recursively through a directory.",
                    "fields": [
                        ("rule", "YARA Rule File", "file", True),
                        ("directory", "Directory", "directory", True),
                    ],
                    "command": lambda v: [
                        "yara", "-r",
                        v["rule"],
                        v["directory"]
                    ]
                }
            }
        },

        "ClamAV": {
            "binary": "clamscan",
            "description": "Open-source antivirus scanner.",
            "operations": {

                "Scan File": {
                    "description": "Scan a file for known malware signatures.",
                    "fields": [
                        ("file", "File", "file", True),
                    ],
                    "command": lambda v: [
                        "clamscan", v["file"]
                    ]
                },

                "Scan Directory": {
                    "description": "Recursively scan a directory.",
                    "fields": [
                        ("directory", "Directory", "directory", True),
                    ],
                    "command": lambda v: [
                        "clamscan", "-r", v["directory"]
                    ]
                }
            }
        },

        "Auditctl": {
            "binary": "auditctl",
            "description": "Linux Audit framework configuration and inspection utility.",
            "operations": {

                "List Rules": {
                    "description": "Display currently loaded audit rules.",
                    "fields": [],
                    "command": lambda v: ["auditctl", "-l"]
                }
            }
        },

        "Lynis": {
            "binary": "lynis",
            "description": "Linux security auditing and hardening tool.",
            "operations": {

                "System Audit": {
                    "description": "Run a security audit of the Linux system.",
                    "fields": [],
                    "command": lambda v: [
                        "lynis", "audit", "system"
                    ]
                }
            }
        }
    },


    # ========================================================
    # CLOUD
    # ========================================================

    "Cloud": {

        "AWS CLI": {
            "binary": "aws",
            "description": "Command-line interface for Amazon Web Services.",
            "operations": {

                "Identity Check": {
                    "description": "Show which AWS identity your CLI is currently using.",
                    "fields": [],
                    "command": lambda v: [
                        "aws", "sts", "get-caller-identity"
                    ]
                },

                "List S3 Buckets": {
                    "description": "List S3 buckets available to the current AWS identity.",
                    "fields": [],
                    "command": lambda v: [
                        "aws", "s3", "ls"
                    ]
                },

                "CLI Help": {
                    "description": "Display AWS CLI help.",
                    "fields": [],
                    "command": lambda v: ["aws", "--help"]
                }
            }
        },

        "Kubectl": {
            "binary": "kubectl",
            "description": "Command-line Kubernetes management tool.",
            "operations": {

                "Cluster Info": {
                    "description": "Display information about the current Kubernetes cluster.",
                    "fields": [],
                    "command": lambda v: [
                        "kubectl", "cluster-info"
                    ]
                },

                "List Pods": {
                    "description": "List pods across all namespaces.",
                    "fields": [],
                    "command": lambda v: [
                        "kubectl", "get", "pods", "-A"
                    ]
                }
            }
        },

        "Helm": {
            "binary": "helm",
            "description": "Kubernetes package manager.",
            "operations": {

                "List Releases": {
                    "description": "Show Helm releases across namespaces.",
                    "fields": [],
                    "command": lambda v: [
                        "helm", "list", "-A"
                    ]
                }
            }
        },

        "Terraform": {
            "binary": "terraform",
            "description": "Infrastructure-as-code platform.",
            "operations": {

                "Version": {
                    "description": "Display the installed Terraform version.",
                    "fields": [],
                    "command": lambda v: [
                        "terraform", "version"
                    ]
                },

                "Validate": {
                    "description": "Validate Terraform configuration in the current workspace.",
                    "fields": [],
                    "command": lambda v: [
                        "terraform", "validate"
                    ]
                }
            }
        },

        "Ansible": {
            "binary": "ansible",
            "description": "Automation and configuration management platform.",
            "operations": {

                "Version": {
                    "description": "Display installed Ansible information.",
                    "fields": [],
                    "command": lambda v: [
                        "ansible", "--version"
                    ]
                }
            }
        }
    },


    # ========================================================
    # DEVSECOPS
    # ========================================================

    "DevSecOps": {

        "Docker": {
            "binary": "docker",
            "description": "Container platform.",
            "operations": {

                "Running Containers": {
                    "description": "Show currently running containers.",
                    "fields": [],
                    "command": lambda v: [
                        "docker", "ps"
                    ]
                },

                "List Images": {
                    "description": "Show local container images.",
                    "fields": [],
                    "command": lambda v: [
                        "docker", "images"
                    ]
                }
            }
        },

        "Docker Compose": {
            "binary": "docker",
            "description": "Docker Compose service orchestration.",
            "operations": {

                "Service Status": {
                    "description": "Show Compose services in the current directory.",
                    "fields": [],
                    "command": lambda v: [
                        "docker", "compose", "ps"
                    ]
                }
            }
        },

        "Trivy": {
            "binary": "trivy",
            "description": "Security scanner for containers, filesystems, repositories, and Kubernetes.",
            "operations": {

                "Scan Container": {
                    "description": "Scan a container image for vulnerabilities.",
                    "fields": [
                        ("image", "Container Image", "text", True, "nginx:latest"),
                    ],
                    "command": lambda v: [
                        "trivy", "image", v["image"]
                    ]
                },

                "Scan Filesystem": {
                    "description": "Scan a local filesystem for vulnerabilities and secrets.",
                    "fields": [
                        ("directory", "Directory", "directory", True),
                    ],
                    "command": lambda v: [
                        "trivy", "fs", v["directory"]
                    ]
                },

                "Scan Repository": {
                    "description": "Scan a source code repository.",
                    "fields": [
                        ("directory", "Repository", "directory", True),
                    ],
                    "command": lambda v: [
                        "trivy", "fs", v["directory"]
                    ]
                }
            }
        },

        "Syft": {
            "binary": "syft",
            "description": "Software Bill of Materials generator.",
            "operations": {

                "Generate SBOM": {
                    "description": "Generate an SBOM from a directory or container image.",
                    "fields": [
                        ("target", "Target", "text", True),
                    ],
                    "command": lambda v: [
                        "syft", v["target"]
                    ]
                }
            }
        },

        "Grype": {
            "binary": "grype",
            "description": "Vulnerability scanner for container images and filesystems.",
            "operations": {

                "Scan Target": {
                    "description": "Search a target for known vulnerabilities.",
                    "fields": [
                        ("target", "Target", "text", True),
                    ],
                    "command": lambda v: [
                        "grype", v["target"]
                    ]
                }
            }
        },

        "Semgrep": {
            "binary": "semgrep",
            "description": "Static analysis tool for finding security and quality issues in source code.",
            "operations": {

                "Scan Project": {
                    "description": "Run Semgrep against a source code directory.",
                    "fields": [
                        ("directory", "Project Directory", "directory", True),
                    ],
                    "command": lambda v: [
                        "semgrep", "scan",
                        v["directory"]
                    ]
                }
            }
        },

        "Gitleaks": {
            "binary": "gitleaks",
            "description": "Detects secrets and credentials accidentally committed to Git repositories.",
            "operations": {

                "Scan Repository": {
                    "description": "Search a repository for exposed secrets.",
                    "fields": [
                        ("directory", "Repository", "directory", True),
                    ],
                    "command": lambda v: [
                        "gitleaks",
                        "detect",
                        "--source", v["directory"]
                    ]
                }
            }
        }
    }
}


# ============================================================
# APPLICATION
# ============================================================

class SecDesk(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title(f"{APP_NAME} {VERSION}")
        self.geometry("1400x900")
        self.minsize(1100, 700)

        self.current_category = None
        self.current_tool = None
        self.current_operation = None

        self.field_vars = {}
        self.field_widgets = {}

        self.process = None
        self.output_queue = queue.Queue()

        self.advanced_mode = tk.BooleanVar(value=False)
        self.dark_mode = tk.BooleanVar(value=False)

        self.setup_style()
        self.build_interface()

        self.select_category("Network")

        self.after(100, self.process_output_queue)

    # ========================================================
    # STYLE
    # ========================================================

    def setup_style(self):

        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "TButton",
            padding=(10, 6)
        )

        style.configure(
            "Accent.TButton",
            padding=(15, 7),
            font=("TkDefaultFont", 10, "bold")
        )

        style.configure(
            "Header.TLabel",
            font=("TkDefaultFont", 18, "bold")
        )

        style.configure(
            "ToolTitle.TLabel",
            font=("TkDefaultFont", 14, "bold")
        )

        style.configure(
            "Small.TLabel",
            font=("TkDefaultFont", 9)
        )

        self.apply_theme()

    def apply_theme(self):

        colors = {
            "window": "#1f2329" if self.dark_mode.get() else "#f4f5f7",
            "surface": "#2b313a" if self.dark_mode.get() else "#ffffff",
            "text": "#e6edf3" if self.dark_mode.get() else "#20252b",
            "muted": "#aab4c0" if self.dark_mode.get() else "#5f6873",
            "border": "#454d58" if self.dark_mode.get() else "#c9ced6",
            "accent": "#4ea1ff" if self.dark_mode.get() else "#1769aa",
            "select": "#315d85" if self.dark_mode.get() else "#cfe8ff",
        }

        style = ttk.Style(self)
        self.configure(background=colors["window"])

        style.configure(
            ".",
            background=colors["window"],
            foreground=colors["text"]
        )
        style.configure("TFrame", background=colors["window"])
        style.configure(
            "TLabel",
            background=colors["window"],
            foreground=colors["text"]
        )
        style.configure(
            "TLabelframe",
            background=colors["window"],
            bordercolor=colors["border"]
        )
        style.configure(
            "TLabelframe.Label",
            background=colors["window"],
            foreground=colors["text"]
        )
        style.configure(
            "TButton",
            background=colors["surface"],
            foreground=colors["text"]
        )
        style.map(
            "TButton",
            background=[("active", colors["select"])],
            foreground=[("active", colors["text"])]
        )
        style.configure(
            "Accent.TButton",
            background=colors["accent"],
            foreground="#ffffff"
        )
        style.map(
            "Accent.TButton",
            background=[("active", colors["select"])]
        )
        style.configure(
            "TEntry",
            fieldbackground=colors["surface"],
            foreground=colors["text"]
        )
        style.configure(
            "TCombobox",
            fieldbackground=colors["surface"],
            foreground=colors["text"]
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", colors["surface"])],
            foreground=[("readonly", colors["text"])]
        )
        style.configure(
            "Header.TLabel",
            background=colors["window"],
            foreground=colors["text"]
        )
        style.configure(
            "ToolTitle.TLabel",
            background=colors["window"],
            foreground=colors["text"]
        )
        style.configure(
            "Small.TLabel",
            background=colors["window"],
            foreground=colors["muted"]
        )

        if hasattr(self, "category_list"):
            self.category_list.configure(
                background=colors["surface"],
                foreground=colors["text"],
                selectbackground=colors["accent"],
                selectforeground="#ffffff"
            )
        if hasattr(self, "output"):
            self.output.configure(
                background=colors["surface"],
                foreground=colors["text"],
                insertbackground=colors["text"]
            )

    def toggle_dark_mode(self):
        self.dark_mode.set(not self.dark_mode.get())
        self.dark_mode_button.configure(
            text="Dark Mode: On" if self.dark_mode.get()
            else "Dark Mode: Off"
        )
        self.apply_theme()

    # ========================================================
    # MAIN UI
    # ========================================================

    def build_interface(self):

        # Header
        header = ttk.Frame(self, padding=(15, 12))
        header.pack(fill="x")

        ttk.Label(
            header,
            text="SecDesk",
            style="Header.TLabel"
        ).pack(side="left")

        ttk.Label(
            header,
            text="  Security Operations Workbench",
            font=("TkDefaultFont", 10)
        ).pack(side="left")

        ttk.Checkbutton(
            header,
            text="Advanced Mode",
            variable=self.advanced_mode,
            command=self.toggle_advanced
        ).pack(side="right")

        self.dark_mode_button = ttk.Button(
            header,
            text="Dark Mode: Off",
            command=self.toggle_dark_mode
        )
        self.dark_mode_button.pack(side="right", padx=(0, 15))

        ttk.Label(
            header,
            text=f"v{VERSION}",
            style="Small.TLabel"
        ).pack(side="right", padx=15)

        ttk.Separator(self).pack(fill="x")

        # Main Paned Window
        main = ttk.PanedWindow(
            self,
            orient="horizontal"
        )
        main.pack(fill="both", expand=True)

        # ----------------------------------------------------
        # Sidebar
        # ----------------------------------------------------

        sidebar = ttk.Frame(main, padding=10)
        main.add(sidebar, weight=1)

        ttk.Label(
            sidebar,
            text="Categories",
            font=("TkDefaultFont", 11, "bold")
        ).pack(anchor="w", pady=(0, 8))

        self.category_list = tk.Listbox(
            sidebar,
            activestyle="none",
            relief="flat",
            highlightthickness=0,
            font=("TkDefaultFont", 10)
        )

        self.category_list.pack(
            fill="both",
            expand=True
        )

        for category in TOOLS:
            self.category_list.insert("end", category)

        self.category_list.bind(
            "<<ListboxSelect>>",
            self.category_changed
        )

        # ----------------------------------------------------
        # Main Workspace
        # ----------------------------------------------------

        center = ttk.Frame(main, padding=15)
        main.add(center, weight=4)

        # Tool selector
        tool_bar = ttk.Frame(center)
        tool_bar.pack(fill="x", pady=(0, 10))

        ttk.Label(
            tool_bar,
            text="Tool:",
            font=("TkDefaultFont", 10, "bold")
        ).pack(side="left")

        self.tool_combo = ttk.Combobox(
            tool_bar,
            state="readonly",
            width=32
        )

        self.tool_combo.pack(
            side="left",
            padx=10
        )

        self.tool_combo.bind(
            "<<ComboboxSelected>>",
            self.tool_changed
        )

        self.status_label = ttk.Label(
            tool_bar,
            text=""
        )
        self.status_label.pack(side="left", padx=10)

        # Tool information
        info_frame = ttk.LabelFrame(
            center,
            text="Tool Information",
            padding=12
        )
        info_frame.pack(
            fill="x",
            pady=(0, 10)
        )

        self.tool_title = ttk.Label(
            info_frame,
            text="",
            style="ToolTitle.TLabel"
        )
        self.tool_title.pack(anchor="w")

        self.tool_description = ttk.Label(
            info_frame,
            text="",
            wraplength=900,
            justify="left"
        )
        self.tool_description.pack(
            anchor="w",
            pady=(5, 0)
        )

        # Operation
        operation_frame = ttk.LabelFrame(
            center,
            text="Operation",
            padding=12
        )
        operation_frame.pack(
            fill="x",
            pady=(0, 10)
        )

        op_row = ttk.Frame(operation_frame)
        op_row.pack(fill="x")

        ttk.Label(
            op_row,
            text="Action:"
        ).pack(side="left")

        self.operation_combo = ttk.Combobox(
            op_row,
            state="readonly",
            width=38
        )

        self.operation_combo.pack(
            side="left",
            padx=10
        )

        self.operation_combo.bind(
            "<<ComboboxSelected>>",
            self.operation_changed
        )

        self.operation_description = ttk.Label(
            operation_frame,
            text="",
            wraplength=900,
            justify="left"
        )

        self.operation_description.pack(
            anchor="w",
            pady=(8, 0)
        )

        # Dynamic fields
        self.fields_frame = ttk.LabelFrame(
            center,
            text="Inputs",
            padding=12
        )

        self.fields_frame.pack(
            fill="x",
            pady=(0, 10)
        )

        # Command preview
        command_frame = ttk.LabelFrame(
            center,
            text="Command Preview",
            padding=10
        )

        command_frame.pack(
            fill="x",
            pady=(0, 10)
        )

        self.command_var = tk.StringVar()

        self.command_entry = ttk.Entry(
            command_frame,
            textvariable=self.command_var,
            state="readonly"
        )

        self.command_entry.pack(
            side="left",
            fill="x",
            expand=True
        )

        ttk.Button(
            command_frame,
            text="Copy",
            command=self.copy_command
        ).pack(
            side="left",
            padx=(8, 0)
        )

        # Action buttons
        actions = ttk.Frame(center)
        actions.pack(
            fill="x",
            pady=(0, 10)
        )

        ttk.Button(
            actions,
            text="Run Operation",
            style="Accent.TButton",
            command=self.run_operation
        ).pack(side="left")

        ttk.Button(
            actions,
            text="Stop",
            command=self.stop_operation
        ).pack(side="left", padx=8)

        ttk.Button(
            actions,
            text="Clear Output",
            command=self.clear_output
        ).pack(side="left")

        ttk.Button(
            actions,
            text="Save Output",
            command=self.save_output
        ).pack(side="left", padx=8)

        # ----------------------------------------------------
        # Output
        # ----------------------------------------------------

        output_frame = ttk.LabelFrame(
            center,
            text="Output",
            padding=8
        )

        output_frame.pack(
            fill="both",
            expand=True
        )

        self.output = tk.Text(
            output_frame,
            wrap="none",
            undo=False,
            font=("TkFixedFont", 10),
            relief="flat"
        )

        self.output.pack(
            side="left",
            fill="both",
            expand=True
        )

        output_scroll = ttk.Scrollbar(
            output_frame,
            orient="vertical",
            command=self.output.yview
        )

        output_scroll.pack(side="right", fill="y")

        self.output.configure(
            yscrollcommand=output_scroll.set
        )

        # Bottom status bar
        ttk.Separator(self).pack(fill="x")

        bottom = ttk.Frame(
            self,
            padding=(10, 5)
        )
        bottom.pack(fill="x")

        self.bottom_status = ttk.Label(
            bottom,
            text=f"Workspace: {WORKSPACE}"
        )

        self.bottom_status.pack(side="left")

        self.process_status = ttk.Label(
            bottom,
            text="Ready"
        )

        self.process_status.pack(side="right")

    # ========================================================
    # CATEGORY
    # ========================================================

    def category_changed(self, event=None):

        selection = self.category_list.curselection()

        if not selection:
            return

        category = self.category_list.get(selection[0])
        self.select_category(category)

    def select_category(self, category):

        self.current_category = category

        tools = list(TOOLS[category].keys())

        self.tool_combo["values"] = tools

        if tools:
            self.tool_combo.current(0)
            self.load_tool(tools[0])

    # ========================================================
    # TOOL
    # ========================================================

    def tool_changed(self, event=None):

        tool = self.tool_combo.get()

        if tool:
            self.load_tool(tool)

    def load_tool(self, tool):

        self.current_tool = tool

        data = TOOLS[
            self.current_category
        ][tool]

        self.tool_title.configure(
            text=tool
        )

        self.tool_description.configure(
            text=data["description"]
        )

        binary = data["binary"]

        if shutil.which(binary):
            self.status_label.configure(
                text="Installed"
            )
        else:
            self.status_label.configure(
                text="Not Found"
            )

        operations = list(
            data["operations"].keys()
        )

        self.operation_combo["values"] = operations

        if operations:
            self.operation_combo.current(0)
            self.load_operation(operations[0])

    # ========================================================
    # OPERATION
    # ========================================================

    def operation_changed(self, event=None):

        operation = self.operation_combo.get()

        if operation:
            self.load_operation(operation)

    def load_operation(self, operation):

        self.current_operation = operation

        self.clear_fields()

        operation_data = TOOLS[
            self.current_category
        ][self.current_tool]["operations"][operation]

        self.operation_description.configure(
            text=operation_data["description"]
        )

        for field in operation_data.get("fields", []):
            self.create_field(field)

        self.update_command()

    # ========================================================
    # DYNAMIC FIELDS
    # ========================================================

    def clear_fields(self):

        for widget in self.fields_frame.winfo_children():
            widget.destroy()

        self.field_vars.clear()
        self.field_widgets.clear()

    def create_field(self, field):

        name = field[0]
        label = field[1]
        field_type = field[2]
        required = field[3]

        default = ""

        if len(field) >= 5:
            default = field[4]

        row = ttk.Frame(self.fields_frame)
        row.pack(
            fill="x",
            pady=4
        )

        label_text = label

        if required:
            label_text += " *"

        ttk.Label(
            row,
            text=label_text,
            width=22
        ).pack(side="left")

        if field_type == "combo":

            values = default

            var = tk.StringVar()

            widget = ttk.Combobox(
                row,
                textvariable=var,
                values=values,
                state="readonly",
                width=50
            )

            if values:
                widget.current(0)

            widget.pack(
                side="left",
                fill="x",
                expand=True
            )

            widget.bind(
                "<<ComboboxSelected>>",
                lambda e: self.update_command()
            )

        else:

            var = tk.StringVar()

            if isinstance(default, str):
                var.set(default)

            widget = ttk.Entry(
                row,
                textvariable=var
            )

            widget.pack(
                side="left",
                fill="x",
                expand=True
            )

            if field_type in (
                "file",
                "directory",
                "file_save"
            ):

                button_text = "Browse"

                ttk.Button(
                    row,
                    text=button_text,
                    command=lambda n=name, t=field_type:
                    self.browse_field(n, t)
                ).pack(
                    side="left",
                    padx=(8, 0)
                )

            var.trace_add(
                "write",
                lambda *args: self.update_command()
            )

        self.field_vars[name] = var
        self.field_widgets[name] = widget

    def browse_field(self, name, field_type):

        if field_type == "directory":

            path = filedialog.askdirectory()

        elif field_type == "file_save":

            path = filedialog.asksaveasfilename(
                initialdir=str(REPORTS)
            )

        else:

            path = filedialog.askopenfilename()

        if path:
            self.field_vars[name].set(path)

    # ========================================================
    # COMMAND BUILDING
    # ========================================================

    def get_values(self):

        values = {}

        for name, var in self.field_vars.items():
            values[name] = var.get().strip()

        return values

    def validate_fields(self):

        operation_data = TOOLS[
            self.current_category
        ][self.current_tool]["operations"][
            self.current_operation
        ]

        values = self.get_values()

        for field in operation_data.get("fields", []):

            name = field[0]
            required = field[3]

            if required and not values.get(name):

                messagebox.showwarning(
                    "Missing Input",
                    f"Please provide: {field[1]}"
                )

                return False

        return True

    def build_command(self):

        if not self.current_operation:
            return []

        operation_data = TOOLS[
            self.current_category
        ][self.current_tool]["operations"][
            self.current_operation
        ]

        values = self.get_values()

        try:
            command = operation_data["command"](values)
        except Exception:
            return []

        return command

    def update_command(self):

        command = self.build_command()

        if not command:
            self.command_var.set("")
            return

        self.command_var.set(
            shlex.join(command)
        )

    # ========================================================
    # ADVANCED MODE
    # ========================================================

    def toggle_advanced(self):

        if self.advanced_mode.get():
            self.bottom_status.configure(
                text=f"Advanced Mode | Workspace: {WORKSPACE}"
            )
        else:
            self.bottom_status.configure(
                text=f"Beginner Mode | Workspace: {WORKSPACE}"
            )

    # ========================================================
    # RUN
    # ========================================================

    def run_operation(self):

        if not self.current_tool:
            return

        if not self.validate_fields():
            return

        command = self.build_command()

        if not command:
            messagebox.showerror(
                "Error",
                "Unable to build command."
            )
            return

        binary = command[0]

        if not shutil.which(binary):

            messagebox.showerror(
                "Tool Not Found",
                f"'{binary}' is not installed or is not in PATH."
            )

            return

        operation_data = TOOLS[
            self.current_category
        ][self.current_tool]["operations"][
            self.current_operation
        ]

        self.clear_output()

        self.write_output(
            f"$ {shlex.join(command)}\n\n"
        )

        if operation_data.get("gui"):

            self.launch_gui(command)
            return

        if operation_data.get("interactive"):

            self.launch_interactive(command)
            return

        self.start_process(command)

    # ========================================================
    # PROCESS
    # ========================================================

    def start_process(self, command):

        if self.process:

            messagebox.showwarning(
                "Process Running",
                "Stop the current operation first."
            )

            return

        self.process_status.configure(
            text="Running..."
        )

        thread = threading.Thread(
            target=self.execute_process,
            args=(command,),
            daemon=True
        )

        thread.start()

    def execute_process(self, command):

        try:

            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                cwd=str(WORKSPACE)
            )

            for line in self.process.stdout:

                self.output_queue.put(
                    ("output", line)
                )

            return_code = self.process.wait()

            self.output_queue.put(
                (
                    "status",
                    f"\nProcess finished with exit code {return_code}\n"
                )
            )

        except Exception as e:

            self.output_queue.put(
                (
                    "status",
                    f"\nERROR: {e}\n"
                )
            )

        finally:

            self.process = None

    # ========================================================
    # GUI / INTERACTIVE
    # ========================================================

    def launch_gui(self, command):

        try:

            subprocess.Popen(
                command,
                cwd=str(WORKSPACE),
                start_new_session=True
            )

            self.write_output(
                "Application launched successfully.\n"
            )

        except Exception as e:

            self.write_output(
                f"Failed to launch application: {e}\n"
            )

    def launch_interactive(self, command):

        terminal = self.find_terminal()

        if not terminal:

            messagebox.showwarning(
                "Terminal Not Found",
                "No supported terminal emulator was detected."
            )

            return

        try:

            command_string = shlex.join(command)

            if terminal == "konsole":

                subprocess.Popen([
                    "konsole",
                    "-e",
                    "bash",
                    "-lc",
                    command_string
                ])

            elif terminal == "gnome-terminal":

                subprocess.Popen([
                    "gnome-terminal",
                    "--",
                    "bash",
                    "-lc",
                    command_string
                ])

            elif terminal == "kgx":

                subprocess.Popen([
                    "kgx",
                    "--",
                    "bash",
                    "-lc",
                    command_string
                ])

            elif terminal == "xfce4-terminal":

                subprocess.Popen([
                    "xfce4-terminal",
                    "--command",
                    f"bash -lc '{command_string}'"
                ])

            else:

                subprocess.Popen([
                    terminal,
                    "-e",
                    "bash",
                    "-lc",
                    command_string
                ])

            self.write_output(
                "Interactive application launched in terminal.\n"
            )

        except Exception as e:

            self.write_output(
                f"Failed to launch terminal: {e}\n"
            )

    def find_terminal(self):

        terminals = [
            "konsole",
            "kgx",
            "gnome-terminal",
            "xfce4-terminal",
            "xterm"
        ]

        for terminal in terminals:

            if shutil.which(terminal):
                return terminal

        return None

    # ========================================================
    # STOP
    # ========================================================

    def stop_operation(self):

        if not self.process:

            self.process_status.configure(
                text="Nothing running"
            )

            return

        try:

            self.process.terminate()

            self.write_output(
                "\nOperation stopped by user.\n"
            )

            self.process_status.configure(
                text="Stopped"
            )

        except Exception as e:

            self.write_output(
                f"\nUnable to stop process: {e}\n"
            )

    # ========================================================
    # OUTPUT
    # ========================================================

    def process_output_queue(self):

        try:

            while True:

                message_type, message = (
                    self.output_queue.get_nowait()
                )

                if message_type == "output":

                    self.write_output(message)

                elif message_type == "status":

                    self.write_output(message)

                    self.process_status.configure(
                        text="Ready"
                    )

        except queue.Empty:
            pass

        self.after(
            100,
            self.process_output_queue
        )

    def write_output(self, text):

        self.output.insert(
            "end",
            text
        )

        self.output.see("end")

    def clear_output(self):

        self.output.delete(
            "1.0",
            "end"
        )

    # ========================================================
    # COPY
    # ========================================================

    def copy_command(self):

        command = self.command_var.get()

        if not command:
            return

        self.clipboard_clear()
        self.clipboard_append(command)

        self.process_status.configure(
            text="Command copied"
        )

    # ========================================================
    # SAVE OUTPUT
    # ========================================================

    def save_output(self):

        content = self.output.get(
            "1.0",
            "end"
        ).strip()

        if not content:

            messagebox.showinfo(
                "Nothing to Save",
                "There is no output to save."
            )

            return

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        default_name = (
            f"{self.current_tool}_"
            f"{timestamp}.txt"
        )

        path = filedialog.asksaveasfilename(
            initialdir=str(REPORTS),
            initialfile=default_name,
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )

        if not path:
            return

        try:

            with open(
                path,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(content)

            self.process_status.configure(
                text="Output saved"
            )

        except Exception as e:

            messagebox.showerror(
                "Save Error",
                str(e)
            )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    app = SecDesk()

    app.mainloop()