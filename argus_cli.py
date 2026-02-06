#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import subprocess
import re
import os
import sys
import socket
import json    
import time
import argparse
import signal

def display_banner():
    banner = r"""
          ___      .______        _______  __    __       _______.
         /   \     |   _  \      /  _____||  |  |  |     /       |
        /  ^  \    |  |_)  |    |  |  __  |  |  |  |    |   (----`
       /  /_\  \   |      /     |  | |_ | |  |  |  |     \   \    
      /  _____  \  |  |\  \----.|  |__| | |  `--'  | .----)   |   
     /__/     \__\ | _| `._____| \______|  \______/  |_______/    
                                                                  
                                          
    -- Linux Rootkit Detection Framework --
    """
    print(banner)
    
    
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
	"listener_list":[
		{
		"ip" : "127.0.0.1",
		"port" : 12345,
		"enabled" : True,
		}
	]
}
def create_config():
	is_sudo = os.getuid() == 0 and 'SUDO_UID' in os.environ
	try:
		if is_sudo:
			orginal_uid = int(os.environ['SUDO_UID'])
			orginal_gid = int(os.environ['SUDO_GID'])
			root_euid = os.geteuid()
			root_egid = os.getegid()
			
			try:
				os.setegid(orginal_gid)
				os.seteuid(orginal_uid)
				with open(CONFIG_FILE , "w") as f:
					json.dump(DEFAULT_CONFIG, f, indent=4)
			except OSError as e:
				print("[!] Error : Could not create config file for the user {} : {}".format(orginal_uid, e))
			finally:
				os.seteuid(root_euid)
				os.setegid(root_egid)
		else:
			with open(CONFIG_FILE, "w") as f:	
				json.dump(DEFAULT_CONFIG, f, indent=4)
		print("[*] Created a sample config file since no configuration file was found. Edit the file and rerun the program")
	except OSError as e:
		print("[x] Error : Could not create config file : {}".format(e))
	except KeyError:
		print("[x] Error : SUDO_UID or SUDO_GID not found in environment. Cannot determine the user.")
	sys.exit(0)
		
	
def load_config():
    if not os.path.exists(CONFIG_FILE):
        create_config()
    with open(CONFIG_FILE,"r") as f:
        return json.load(f)
        
        
def send_udp_alert(findings, config):
    if not findings:
        return
    message = "\n".join(findings)
    sent_count = 0
    for listener in config.get("listener_list", []):
        if not listener.get("enabled", False):
            continue
        ip = listener["ip"]
        port = listener["port"]
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(message.encode('utf-8'), (ip, port))
            sent_count += 1
        except Exception as e:
            print("[!] UDP send failed ({}:{}): {}".format(ip, port, e))
        finally:
            if s:
                s.close()
    if sent_count > 0:
        print("[+] UDP alert sent to {} listener(s).".format(sent_count))
        
...

def signal_handler(signum, frame):
    print("Daemon shutting down...")
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except OSError as e:
        sys.stderr.write("Error removing PID file: {}\n".format(e))
    sys.exit(0)


def daemon_worker(interval, config):
   
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    print("[*] Argus daemon started (PID: {}). Running scans every {} seconds.".format(os.getpid(), interval))
    while True:
        try:
            all_findings = []
            original_stdout = sys.stdout
            sys.stdout = open(os.devnull, 'w')
            
            all_findings.extend(run_process_scan())
            all_findings.extend(run_module_scan())
            all_findings.extend(run_port_scan())
            
            sys.stdout.close()
            sys.stdout = original_stdout
            
            if all_findings:
                print("[{}] Daemon detected {} anomalies. Sending alert.".format(time.ctime(), len(all_findings)))
                send_udp_alert(all_findings, config)

        except Exception as e:
            sys.stderr.write("[!] Error in daemon loop: {}\n".format(e))
        
        time.sleep(interval)


def daemonize():
   
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                old_pid = int(f.read().strip())
            os.kill(old_pid, 0)
            sys.stderr.write("Daemon is already running with PID {}. Aborting.\n".format(old_pid))
            sys.exit(1)
        except (OSError, ValueError):
            os.remove(PID_FILE)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write("fork #1 failed: {}\n".format(e))
        sys.exit(1)

    os.chdir("/")
    os.setsid()
    os.umask(0)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write("fork #2 failed: {}\n".format(e))
        sys.exit(1)

    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
    except OSError as e:
        sys.stderr.write("Unable to write PID file {}: {}\n".format(PID_FILE, e))
        sys.exit(1)


    sys.stdout.flush()
    sys.stderr.flush()
    si = open(os.devnull, 'r')
    so = open(os.devnull, 'a+')
    se = open(os.devnull, 'a+')
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


def stop_daemon():
    if not os.path.exists(PID_FILE):
        sys.stderr.write("Daemon is not running (PID file not found).\n")
        return

    try:
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
    except (ValueError, IOError) as e:
        sys.stderr.write("Error reading PID file: {}\n".format(e))
        os.remove(PID_FILE)
        return

    try:
        print("Stopping daemon with PID {}...".format(pid))
        os.kill(pid, signal.SIGTERM)

        time.sleep(1)

        os.kill(pid, 0) 
        print("Daemon did not stop gracefully, sending SIGKILL.")
        os.kill(pid, signal.SIGKILL)

    except OSError:
        print("Daemon stopped successfully.")
    finally:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
...
def interactive_menu(config):
    stat = False
    display_banner()
    while True:
        display_menu(stat)
        try:
            choice = raw_input("Argus > ")
            if choice == '1':
                findings = run_process_scan()
                if stat and findings:
                    send_udp_alert(findings, config)
            elif choice == '2':
                findings = run_module_scan()
                if stat and findings:
                    send_udp_alert(findings, config)
            elif choice == '3':
                findings = run_port_scan()
                if stat and findings:
                    send_udp_alert(findings, config)
            elif choice == '4':
                findings = run_full_scan()
                if stat and findings:
                    send_udp_alert(findings, config)
            elif choice == '5':
                stat = not stat
                print("[+] UDP alerts {}".format('ENABLED' if stat else 'DISABLED'))
            elif choice == '99':
                print("System observation terminated." + "\n" +"ARGUS sleeps")
                break
            else:
                print("Unknown command: {}".format(choice))
        except KeyboardInterrupt:
            print("\nSystem observation terminated. ARGUS sleeps.")
            break
        except Exception as e:
            print("\nAn unexpected error occurred: {}".format(e))
            
            
            
if __name__ == "__main__":
    main()
