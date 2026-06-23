# Command Injection Test Case — CWE-78, OWASP A03:2021
# This file contains INTENTIONAL vulnerabilities for testing the security scanner.

import os
import subprocess

def ping_host(host):
    """VULNERABLE: Command injection via os.system"""
    # VULNERABILITY: User input directly in shell command
    os.system(f"ping {host}")

def lookup_dns(domain):
    """VULNERABLE: Command injection via subprocess with shell=True"""
    # VULNERABILITY: shell=True with user input
    result = subprocess.check_output(f"nslookup {domain}", shell=True)
    return result.decode()

def convert_file(filename, output_format):
    """VULNERABLE: Command injection via os.popen"""
    # VULNERABILITY: User-controlled filename in command
    stream = os.popen(f"convert {filename} output.{output_format}")
    return stream.read()

def execute_user_code(code_string):
    """VULNERABLE: Code execution via eval"""
    # VULNERABILITY: eval with user input
    result = eval(code_string)
    return result

def run_dynamic(command):
    """VULNERABLE: exec with user input"""
    # VULNERABILITY: exec with dynamic input
    exec(command)

# SAFE EXAMPLE:
# subprocess.run(["ping", "-c", "4", host], capture_output=True)  # List args, no shell
