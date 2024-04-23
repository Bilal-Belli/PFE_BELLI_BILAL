import xml.etree.ElementTree as ET
import xml.dom.minidom
import json

file_path = 'filtered_output.txt'
json_file = 'infos_sidestore.json'

def separateFunction2Blocs(lines,minbound,maxbound):
    branch_ARM64_mnemonic_OneArgument = ['b'] # Add: bl
    branch_ARM64_mnemonic_TwoArguments = ['cbz','cbnz']
    branch_ARM64_mnemonic_ThreeArguments = ['tbnz','tbz']

    branch_addresses = set()
    branch_following_addresses = set()
    for ii in range(len(lines)):
        parts = lines[ii].strip().split('\t')
        if len(parts) < 2:
            continue  # Skip lines with less than two parts : nop operations ex: @@@@@@ nop

        # parts[0] : address
        # parts[1] : opcode ex: mov
        # parts[2] : rest/operands

        mnemonic = parts[1]
        if ii < len(lines) - 1:
            next_address = lines[ii + 1].strip().split('\t')[0]
        else:
            next_address = None

        # distinct between one argument instructions and multiple arguments instructions
        if (mnemonic.startswith('b.') or (mnemonic in branch_ARM64_mnemonic_OneArgument)): # One argument
            if (next_address is not None):
                branch_addresses.add(next_address)  # Address of the next line
            target_address = parts[2].replace('0x', '').split(' ;')[0]  # Remove '0x' prefix
            if (int(target_address,16)>=minbound and int(target_address,16)<=maxbound):
                branch_following_addresses.add(target_address)
        else:
            if (mnemonic in branch_ARM64_mnemonic_TwoArguments): # Two arguments
                if (next_address is not None):
                    branch_addresses.add(next_address)  # Address of the next line
                operands = parts[2].strip().split(', ')
                # example : @ cbz x12, 0x1320990
                target_address = operands[1].replace('0x', '')  # Remove '0x' prefix
                if (int(target_address,16)>=minbound and int(target_address,16)<=maxbound):
                    branch_following_addresses.add(target_address)
            else:
                if (mnemonic in branch_ARM64_mnemonic_ThreeArguments): # Three arguments
                    if (next_address is not None):
                        branch_addresses.add(next_address)  # Address of the next line
                    operands = parts[2].strip().split(', ')
                    # example : @ tbz x12, #0, 0x1320990
                    target_address = operands[2].replace('0x', '')  # Remove '0x' prefix
                    if (int(target_address,16)>=minbound and int(target_address,16)<=maxbound):
                        branch_following_addresses.add(target_address)

    # Block start addresses
    block_start_addresses = sorted(branch_addresses.union(branch_following_addresses))
    # Divide code into blocks
    blocks = []
    start_index = 0

    for i, addr in enumerate(block_start_addresses):
        try:
            end_index = lines.index(next(filter(lambda x: addr in x, lines[start_index:])), start_index)
            block = lines[start_index:end_index ]
            if block!=[]:
                blocks.append(lines[start_index:end_index ])
        except:
            continue
        start_index = end_index

    # Add the remaining code after the last block
    if start_index < len(lines):
        blocks.append(lines[start_index:])
    return blocks

def read_json_objects(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON in file '{file_path}': {e}")
        return None

def read_first_and_last_line_and_get_addresses(lines):
    first_adress = lines[0].split('\t')[0].strip()
    last_adress = lines[-1].split('\t')[0].strip()
    return first_adress, last_adress

def select_lines_between_prefixes(lines, objects):
    selected_lines = []
    within_range = False
    functionXMLelements = []
    iterator = 0
    tailleJson = len(objects)
    adressDebutJson = objects[iterator]['minbound']
    adressFinJson = objects[iterator]['maxbound']
    for line in lines:
        if line.startswith(adressDebutJson):
            within_range = True
        if line.startswith(adressFinJson): # sauvgarde de selected_lines
            within_range = False
            iterator+=1
            if tailleJson == iterator:
                # la fin de la boucle
                break
            else: # initialisation pour la nouvelle fonction
                previous_maxbound = adressFinJson
                signature_fonction = objects[iterator]['signature']
                blocks = separateFunction2Blocs(selected_lines, int(adressDebutJson, 16), int(adressFinJson, 16))
                functionXMLelements.append(constructXMLfunction(signature_fonction, previous_maxbound, blocks))
                selected_lines = []
                adressDebutJson = objects[iterator]['minbound']
                adressFinJson = objects[iterator]['maxbound']
                while (int(adressDebutJson,16)<int(previous_maxbound,16)):
                    iterator+=1
                    previous_maxbound = adressFinJson
                    adressDebutJson = objects[iterator]['minbound']
                    adressFinJson = objects[iterator]['maxbound']
        if within_range:
            selected_lines.append(line)
    writeInXMLfile("program.xml",functionXMLelements)

def writeInXMLfile(file_path, functionXMLelements):
    program = ET.Element("Program")
    tree = ET.ElementTree(program)
    root = tree.getroot()
    # Add <Function> under <Program>
    for function in functionXMLelements:
        root.append(function)
    # Convert the XML tree to a formatted string
    xml_str = ET.tostring(root, encoding='utf-8')
    formatted_xml = xml.dom.minidom.parseString(xml_str).toprettyxml(indent="  ")
    # Write the formatted XML to the file
    with open(file_path, "w") as f:
        f.write(formatted_xml)

def constructXMLfunction(signature, startAdress, blocks):
    # <Function> Element
    function = ET.Element("Function")
    function.set('id', startAdress) # ID attribute
    name, parametres = recupererName_Parametres(signature)
    function.set('name', name) # name attribute
    # Parameters Elements
    if parametres[0] != '':
        parametres_XML = ET.Element("Parameters")
        i = 0
        for para in parametres:
            parametre_XML = ET.Element("Parameter")
            parts1 = para.split(' ')
            parametre_XML.set('type', parts1[0])
            parametre_XML.set('name', parts1[1])
            parametres_XML.append(parametre_XML)
        function.append(parametres_XML)
    
    # Blocks Elements
    for block in blocks:
        block_XML = ET.Element("Block")
        id = block[0].strip().split('\t')[0]
        block_XML.set('id', id)
        for line in block:
            parts = line.strip().split('\t')
            instruction_XML = ET.Element("Instruction")
            instruction_XML.set('opcode', parts[1])
            # instruction_XML.set('dest', "z")
            # instruction_XML.set('src', "z")
            block_XML.append(instruction_XML)
        function.append(block_XML)
    return function

def recupererName_Parametres(signature):
    signature = signature.strip().split(' (')
    name = signature[0]
    parametres = signature[1].replace(');', '').strip().split(', ')
    return name, parametres

with open(file_path, 'r') as file:
    lines = file.readlines()
    objects = read_json_objects(json_file)
    functionXMLelements = []
    if objects:
        # create_xml_file("program.xml")
        select_lines_between_prefixes(lines, objects)