input_file = r"C:\Users\Hp\OneDrive\Bureau\cleanDIS\assembles\disassembly_sidestore_swift.txt"
output_file = "filtered_output.txt"

with open(input_file, "r") as f:
    lines = f.readlines()

# Filter lines starting with "00" (not sure-need to test a lot of programs)
filtered_lines = [line for line in lines if line.strip().startswith("00")]

# Modify addresses to remove leading zeros (get only offset)
modified_lines = [line.lstrip('0') for line in filtered_lines]

# Write modified lines to the output file
with open(output_file, "w") as f:
    f.writelines(modified_lines)