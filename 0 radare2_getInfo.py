import os, subprocess

def execute_r2_command(command):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        output, error = process.communicate()
        return output, error
    except Exception as e:
        return None, str(e)

file_path = r"C:\Users\Hp\OneDrive\Bureau\machos\SideStore"
destination_file_path = "infos_sidestore"

get_info_command = f'r2 -e bin.cache=true -qc "aas;aflj > {destination_file_path}.json" "{file_path}"'
execute_r2_command(get_info_command)