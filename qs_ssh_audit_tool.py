# ----------------------------
# ssh auith
# ----------------------------
import subprocess
import json
import logging

def audit_ssh_host(hostname, port=22):
    command = ["ssh-audit", hostname, "-p", str(port), "-j"]

    try:
        print(f"Runing command {command}")

        process = subprocess.run(
            command,
            capture_output=True, # Capture stdout and stderr
            text=True,           # Decode output as text (string)
            check=True           # Raise CalledProcessError if command fails
        )

        if process.returncode == 0:
            print(f"Command {command[0]} executed successfully, no veneralibities discovered.")
            return None
        else:
            print(f"Command {command[0]} failed with exit code: {process.returncode}")
            return None 
    except subprocess.CalledProcessError as e:
        # TODO: investigate other response codes
        if e.returncode == 3:
            #print(f"Command {command[0]} returned with non-zero exit code: {e.returncode}")
            result_json_object = {}

            try:
                json_output = json.loads(e.output)
                target = json_output.get('target')

                result_json_object['target'] = target

                for key, value in json_output.items():
                    if key == 'additional_notes':
                        if len(value) > 0:
                            result_json_object[key] = value
                    elif key == 'recommendations':
                        # TODO: handle recommendations
                        if logging.getLogger() == logging.INFO:
                            print("recommendations found")
                    elif key == 'banner':
                        if logging.getLogger() == logging.INFO:
                            print(f"banner: {value.get('software')}")
                    elif key == 'compression':
                        if logging.getLogger() == logging.INFO:
                            print(f"compression: {value[1]}")
                    elif key == 'fingerprints':
                        if logging.getLogger() == logging.INFO:
                            for v in value:
                                print(f"fingerprint: {v.get('hash')}, {v.get('hash_alg')}, {v.get('hostkey')}")
                    elif key == 'target':
                        if logging.getLogger() == logging.INFO:
                            print(f"target: {value}")
                    else:
                        for v in value:
                            processed_result = process_ssh_note(target, key, v.get('algorithm'), v.get('notes'))
                            if processed_result:
                                result_json_object[v.get('algorithm')] = processed_result
                return result_json_object
            except json.JSONDecodeError:
                print("Failed to decode JSON output.")
            except Exception as e:
                print(f"General json exception: {e}")
            return None
        print(f"Error running {command[0]} code: {e.returncode}, output: {e.output}")
    except FileNotFoundError:
        print(F"Error: {command[0]} command not found. Ensure it's installed and in your PATH.")
    
def process_ssh_note(host, ssh_group, ssh_item, notes):

    if len(notes.items()) > 0 and logging.getLogger() == logging.INFO:
        print(f"Processing note: {ssh_item} with notes: {len(notes.items())}")

    results = None
    for key, value in notes.items():
        if key == 'info' and logging.getLogger() == logging.INFO:
            print(f"{ssh_group} {ssh_item} {key}: {value}[0]")
        #TODO: fix this
        if key == 'warn': # and logging.getLogger() == logging.WARNING:
            #print(f"{ssh_group} {ssh_item} {key}: {value[0]}")
            results = {}
            results['Severity'] = key
            results['Message'] = value
        # always handle fail level
        if key == 'fail':
            #print(f"{ssh_group} {ssh_item} {key}: {value[0]}")
            results = {}
            results['Severity'] = key
            results['Message'] = value
    return results
