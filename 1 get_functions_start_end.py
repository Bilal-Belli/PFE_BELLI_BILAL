import json

json_file = 'infos_sidestore.json'

# Load JSON data from file
with open(json_file) as f:
    data = json.load(f)

# Filter, convert offsets to hex, and sort the data
sorted_data = sorted([
    {
        "minbound": format(item["minbound"], '02x'),
        "maxbound": format(item["maxbound"], '02x'),
        "signature": item["signature"]
    }
    for item in data
], key=lambda x: int(x["minbound"], 16))

# Write the sorted data back to the same JSON file
with open(json_file, 'w') as f:
    json.dump(sorted_data, f, indent=2)