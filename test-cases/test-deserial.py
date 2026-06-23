# Insecure Deserialization Test Case — CWE-502, OWASP A08:2021
# This file contains INTENTIONAL vulnerabilities for testing the security scanner.

import pickle
import yaml
import json

def load_user_session(session_data):
    """VULNERABLE: Pickle deserialization of untrusted data"""
    # VULNERABILITY: pickle.loads with user-controlled data = RCE
    user = pickle.loads(session_data)
    return user

def load_from_file(filepath):
    """VULNERABLE: Pickle load from file"""
    # VULNERABILITY: Loading pickled data from potentially untrusted source
    with open(filepath, 'rb') as f:
        data = pickle.load(f)
    return data

def parse_config(yaml_string):
    """VULNERABLE: YAML load without safe loader"""
    # VULNERABILITY: yaml.load without Loader= can execute arbitrary Python
    config = yaml.load(yaml_string)
    return config

def dangerous_eval_json(json_string):
    """VULNERABLE: Using eval to parse JSON"""
    # VULNERABILITY: eval on user input disguised as JSON parsing
    data = eval(json_string)
    return data

class MaliciousPayload:
    """Example of what an attacker can do with pickle deserialization"""
    def __reduce__(self):
        import os
        return (os.system, ('echo pwned',))

# SAFE EXAMPLES:
# json.loads(json_string)  # Use json.loads instead of eval
# yaml.safe_load(yaml_string)  # Use safe_load
# yaml.load(yaml_string, Loader=yaml.SafeLoader)  # Specify SafeLoader
# # For pickle: Don't use pickle with untrusted data. Use JSON or MessagePack instead.
