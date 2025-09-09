from datetime import datetime
import json, os
import psutil, socket

# Utility function to get the current timestamp in "YYYYMMDD_HHMM" format
def get_current_timestamp():
    now = datetime.now()

    return now.strftime("%Y%m%d_%H%M")

# dump json data to a file
def dump_json_to_file(json_object, output_dir, tag, host):
    
    if json_object:
        json_object["schema"] = "qs-cbom:v0.3"
        json_object["generated_at"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z")
        json_object["policy_refs"] = "[\"CNSA 2.0\", \"FIPS 203-205\"]"

    if output_dir:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
    else:
        print("no OUTPUT_DIR set; using current directory")
        output_dir = "."

    output_file = f"{output_dir}/{tag}_{host}.json"
    print(f"writing to {output_file} ...")
    if json_object:
        with open(output_file, 'w') as f:
            json.dump(json_object, f, indent=2)

def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

def get_ip_address_of_interface(interface_name):
    # Retrieves the IPv4 address of a specified network interface.
    addresses = psutil.net_if_addrs()
    if interface_name in addresses:
        for addr in addresses[interface_name]:
            if addr.family == socket.AF_INET:  # Check for IPv4 addresses
                print(f"discoered hosted interface {interface_name} with IP {addr.address}")
                return addr.address
    return None