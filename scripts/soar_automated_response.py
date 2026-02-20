# Automated SOAR Response Script via SSH Tunneling
# Created by: Leo Martinez III | Spring 2026

"""
Description:
This script acts as a custom SOAR playbook. It polls the Security Onion Elasticsearch API 
(via a local SSH tunnel) for recent Suricata threat alerts. It parses the Elastic Common 
Schema (ECS) to extract malicious IP addresses, then uses Paramiko to establish an SSH 
session with the victim machine and dynamically injects iptables drop rules to contain the threat.

Documentation: 
See the corresponding demonstration report in the /reports/ directory.
"""

import requests
from requests.auth import HTTPBasicAuth
import urllib3
import paramiko # Required for the SSH Automated Response

# Suppress SSL warnings (optional, it is self-signed)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def block_attacker_on_victim(attacker_ip):
    """
    Automated Response Phase:
    SSH into the victim machine (Metasploitable) and use iptables to drop traffic from the attacker.
    """
    # Note: In a production environment, use SSH keys, not hardcoded passwords!
    victim_ip = "192.168.1.54" # This was generated on the victim machine via DHCP
    ssh_user = "msfadmin" # Default user/pass for this VM
    ssh_pass = "msfadmin"
    
    print(f"\n[>>>] Executing SOAR Playbook: Blocking {attacker_ip} on Victim VM ({victim_ip})...")
    
    try:
        # 1. Setup the SSH client
        ssh = paramiko.SSHClient()
        # Automatically trust the remote server's SSH key (useful for lab environments)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) 
        
        # 2. Establish the connection
        ssh.connect(victim_ip, username=ssh_user, password=ssh_pass, timeout=5)
        
        # 3. Construct the iptables command
        # Because iptables requires root, we use sudo. 
        # We echo the password into sudo -S so it executes silently without a prompt.
        firewall_command = f"echo {ssh_pass} | sudo -S iptables -A INPUT -s {attacker_ip} -j DROP"
        
        # 4. Execute the command
        stdin, stdout, stderr = ssh.exec_command(firewall_command)
        
        # 5. Check execution status
        error = stderr.read().decode().strip()
        print(f"[SUCCESS] iptables rule applied. Traffic from {attacker_ip} is dropped!")
        
        # Clean up the session
        ssh.close()
        
    except Exception as e:
        print(f"[ERROR] Automated response failed: {e}")

# ==========================================
# MAIN ORCHESTRATION SCRIPT
# ==========================================

# so_ip = "192.168.1.50"  # Security Onion IP (Direct)
so_ip = "127.0.0.1"       # Routed through secure SSH Local Port Forwarding tunnel

# 1. Connect through your SSH tunnel to search all indices
url = f"https://{so_ip}:9200/*/_search"

# 2. The ECS Query: Find any event where the attacker (Kali) is the source in the last 10 minutes
query_payload = {
    "size": 50, # looking at up to 50 logs at once
    "query": {
        "bool": {
            "must": [
                { "match": { "source.ip": "10.10.10.6" } }
            ],
            "filter": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": "now-10m",
                            "lte": "now"
                        }
                    }
                }
            ]
        }
    }
}

# 3. Authenticate and make the request
# Note: In a real work environment, credentials should be pulled from a .env file!
username = "onionadmin@lab.local"
password = "password"

try: 
    # We use verify=False because Security Onion uses self-signed certificates locally
    response = requests.get(
        url, 
        auth=HTTPBasicAuth(username, password), 
        json=query_payload, 
        verify=False
    )
    
    if response.status_code == 200:
        data = response.json()
        hits = data.get('hits', {}).get('hits', [])
        
        print(f"\n--- Poll completed. Found {len(hits)} events from Kali in the last 10 minutes. ---")
        
        # Initialize a set to deduplicate IPs so we don't SSH 50 times for the same attacker
        malicious_ips = set()
        
        # 4. Parse the nested ECS JSON
        for hit in hits:
            source = hit.get('_source', {})
            
            # Navigate the network dictionaries safely
            source_ip = source.get('source', {}).get('ip', 'Unknown')
            dest_ip = source.get('destination', {}).get('ip', 'Unknown')
            
            # --- Extract the human-readable alert description ---
            # First, try the standard ECS rule name location
            alert_name = source.get('rule', {}).get('name') 
            
            # If that is empty, dig into the Suricata-specific schema
            if not alert_name:
                alert_name = source.get('suricata', {}).get('eve', {}).get('alert', {}).get('signature')
                
            # If it still can't find it, fall back to the raw message or a generic string
            if not alert_name:
                alert_name = source.get('message', 'Generic Suricata Alert')

            # Print the highly descriptive alert
            print(f"[!] Threat Signature: {alert_name}")
            print(f"    Traffic: {source_ip} --> {dest_ip}")
            print(f"    ACTION LOGGED: Need to block {source_ip} on Victim VM")
            print("-" * 50)
            
            # Add the IP to our set for the automated response phase
            if source_ip and source_ip != 'Unknown':
                malicious_ips.add(source_ip)
                
        # 5. Execute the Automated Response
        if malicious_ips:
            print("\n--- Initiating SOAR Automated Response Phase ---")
            for ip in malicious_ips:
                block_attacker_on_victim(ip)
        else:
            print("\nNo actionable IP addresses found. Standing by.")
                
    else:
        print(f"Failed. Status Code: {response.status_code}")

except Exception as e:
    print(f"An error occurred: {e}")
