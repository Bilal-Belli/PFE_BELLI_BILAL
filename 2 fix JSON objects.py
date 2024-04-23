import json

file_path = 'filtered_output.txt'
json_file = 'infos_sidestore.json'

def read_json_objects(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def read_first_and_last_line_and_get_addresses(lines):
    first_address = lines[0].split('\t')[0].strip()
    last_address = lines[-1].split('\t')[0].strip()
    return first_address, last_address

def update_json_file(objects):
    with open(json_file, 'w') as file:
        json.dump(objects, file, indent=4)
    print("JSON file updated successfully.")

with open(file_path, 'r') as file:
    objects = read_json_objects(json_file)
    if objects:
        debut_fichier_assembleur, fin_fichier_assembleur = read_first_and_last_line_and_get_addresses(file.readlines())
        debut_fichier_assembleur_decimal = int(debut_fichier_assembleur, 16)
        fin_fichier_assembleur_decimal = int(fin_fichier_assembleur, 16)
        updated_objects = []
        for obj in objects:
            minbound_decimal = int(obj['minbound'], 16)
            maxbound_decimal = int(obj['maxbound'], 16)
            if minbound_decimal < debut_fichier_assembleur_decimal or maxbound_decimal > fin_fichier_assembleur_decimal:
                continue  # The function is not in the __text section
            else:
                updated_objects.append(obj)  # The function exists in the assembly code
        update_json_file(updated_objects)