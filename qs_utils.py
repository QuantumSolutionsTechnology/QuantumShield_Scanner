from datetime import datetime
import json, os

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
        print(f"ensuring {output_dir} exists")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
    else:
        print("no OUTPUT_DIR set; using current directory")
        output_dir = "."

    output_file = f"{output_dir}/{tag}_{host}.json"
    print(f"using {output_file} json results")
    if json_object:
        with open(output_file, 'w') as f:
            json.dump(json_object, f, indent=2)