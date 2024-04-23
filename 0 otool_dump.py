import os, subprocess

def execute_otool_command(command):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        output, error = process.communicate()
        return output, error
    except Exception as e:
        return None, str(e)

file_path = r"C:\Users\Hp\OneDrive\Bureau\machos\SideStore"
destination_file_path = "disassembly"

get_info_command = f'otool -tV > "{destination_file_path}.txt" "{file_path}"'
execute_otool_command(get_info_command)