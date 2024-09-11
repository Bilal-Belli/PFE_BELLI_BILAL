import os, platform, subprocess, json
import xml.etree.ElementTree as ET
import xml.dom.minidom
import re
import cpp_demangle

registresArguments = ['w0','w1','w2','w3','w4','w5','w6','w7','x0','x1','x2','x3','x4','x5','x6','x7']

# This function determines which operating system is executing the script (macOS, Windows, or Linux)
def checkWhichOS():
    osPlatformName = platform.system()
    if osPlatformName == "Darwin":
        return 1 # Using Otool is possible in this case
    else:
        return 0 # Using Otool is NOT possible in this case
# #############################
# This function allows executing a shell command and returns the result
def executeCommand(command):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        output, error = process.communicate()
        return output, error
    except Exception as e:
        return None, str(e)
# #############################
# This function allows you to get the file name from a given path
def getFileNameFromPath(filePath):
    try:
        return os.path.basename(filePath)
    except FileNotFoundError:
        print("file not found error")
# #############################
# This function removes leading zeros from the offsets and eliminates non-assembly code lines
def filterDisassembly(disassemblyFilePath):
    try:
        with open(disassemblyFilePath, "r") as f:
            lines = f.readlines()
        # Lines that they don't start with address
        filteredLines = [line for line in lines if line.strip().startswith("00")]
        # Leading zeros
        editedLines = [line.lstrip('0') for line in filteredLines]
        filtredDisassemblyFilePath = os.path.dirname(disassemblyFilePath) + "filtred" + os.path.basename(disassemblyFilePath)
        with open(filtredDisassemblyFilePath, "w") as f:
            f.writelines(editedLines)
        return filtredDisassemblyFilePath
    except FileNotFoundError:
        print("file not found error")
# #############################
# This function retrieves only the necessary information, converts offsets to hex, and sorts the data
def filterJsonInfos(infosJsonFilePath):
    try:
        with open(infosJsonFilePath) as f:
            data = json.load(f)
        sorted_data = sorted([
            {
                "minbound": format(item["minbound"], '02x'),
                "maxbound": format(item["maxbound"], '02x'),
                "signature": item["signature"]
            }
            for item in data
        ], key=lambda x: int(x["minbound"], 16))
        with open(infosJsonFilePath, 'w') as f:
            json.dump(sorted_data, f, indent=2)
    except FileNotFoundError:
        print("file not found error")
# #############################
# This function reads a JSON file and returns its content as an object
def readJsonObjects(jsonFilePath):
    try:
        with open(jsonFilePath, 'r') as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        print("file not found error")
# #############################
# This function get the first and last offsets
def getFirstLastAddresses(lines):
    try:
        first_address = lines[0].split('\t')[0].strip()
        last_address = lines[-1].split('\t')[0].strip()
        return first_address, last_address
    except IndexError as e:
        print("error when getting first and last addresses | index out of range")
    except Exception as e:
        print("error when getting first and last addresses : "+e)
# #############################
# This function allows to write updates on a json file
def updateInfosJsonFile(objects, infosJsonFile):
    try:
        with open(infosJsonFile, 'w') as file:
            json.dump(objects, file, indent=4)
    except FileNotFoundError:
        print("file not found error")
# #############################
# This function filters and removes unavailable functions in the `_text` section from a JSON file
def keepOnlyDisassembledFunctions(disassemblyTextFilePath, infosJsonFile):
    try:
        with open(disassemblyTextFilePath, 'r') as file:
            objects = readJsonObjects(infosJsonFile)
            if objects:
                debut_fichier_assembleur, fin_fichier_assembleur = getFirstLastAddresses(file.readlines())
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
                updateInfosJsonFile(updated_objects, infosJsonFile)
    except FileNotFoundError:
        print("file not found error")
# #############################
# This function demangles Objective-C names
def demangleObjc(mangledName):
    try:
        demangledName = cpp_demangle.demangle(mangledName)
        return demangledName
    except Exception as e:
        return mangledName
# #############################
# This function demangles Swift names
def demangleSwift(mangledName):
    try:
        result = subprocess.run('swift-demangle', input=mangledName.encode(), capture_output=True, check=True)
        # result = subprocess.run(['swift-demangle', '--simplified', '--compact'], input=mangledName.encode(), capture_output=True, check=True)
        demangledName = result.stdout.decode().strip()
        # demangledName = re.sub(r'\(.*$', '', demangledName)
        # demangledName = demangledName.replace(" ", "_").replace("<", "_").replace(">", "_")
        return demangledName
    except Exception as e:
        return mangledName
# #############################
# This function return an object {"nomVarSrc":... ,"nomVarSrc":...}
def createVariableObject(nomVariableDestination, nomVariableSource):
    return {
        "nomVarDest": nomVariableDestination,
        "nomVarSrc": nomVariableSource
    }
# #############################
# This function return an object {"type":...,"condition":...,"true":...,"false":...}
def create_condition_object(condition, true, false):
    return {
        "type": "condition",
        "condition": condition,
        "true": true,
        "false": false
    }
# #############################
# This function return an object {"type":...,"target":...}
def create_incondition_object(target):
    return {
        "type": "incondition",
        "target": target,
    }
# #############################
# This function return an object {"type":... ,"suivante":...}
def create_logique_object(suivante):
    return {
        "type": "suite_logique",
        "suivante": suivante
    }
# #############################
# This function checks whether a binary variable is immediate or not
def checkIfImmediate(var):
    if str(var).startswith("#"):
        return True
    else:
        return False
# #############################
# This function exploits a function signature to retrieve parameter names and their count
def getNameAndNumberOfParametres(signature):
    try:
        splitedParts = signature.strip().split(' (')
        return splitedParts[0], len(splitedParts[1].replace(');', '').strip().split(', '))
    except IndexError:
        print("error when getting name and number of parameters")
# #############################
# This function selects lines within JSON object bounds and then processes the transformation to IR
def selectLinesAndProcessTransformationToRI(lines, objects, xmlDestiationFile):
    selected_lines = []
    within_range = False
    functionXMLelements = []
    iterator = 0
    tailleJson = len(objects)
    adressDebutJson = objects[iterator]['minbound']
    adressFinJson = objects[iterator]['maxbound']
    for line in lines:
        variables = {}
        listeArguments = {}
        retour = {}
        if line.startswith(adressDebutJson):
            within_range = True
        if line.startswith(adressFinJson): # sauvgarde de selected_lines
            within_range = False
            iterator+=1
            if tailleJson == iterator:
                # la fin de la boucle
                break
            else: # initialisation pour la nouvelle fonction
                previous_minbound = adressDebutJson
                previous_maxbound = adressFinJson
                signature_fonction = objects[iterator-1]['signature']

                nomFonct, nombreParametres = getNameAndNumberOfParametres(signature_fonction)
                variables, listeArguments, retour = recupererVariables(selected_lines, nombreParametres)

                blocks, control_flow = separateFunction2Blocks(selected_lines, int(adressDebutJson, 16), int(adressFinJson, 16), variables)
                functionInXML = constructXMLfunction(nomFonct, previous_minbound, blocks, control_flow, variables, listeArguments, retour)
                if len(functionInXML) != 0:
                    # function element cant be empty
                    functionXMLelements.append(functionInXML)
                selected_lines = []
                adressDebutJson = objects[iterator]['minbound']
                adressFinJson = objects[iterator]['maxbound']
                if (int(adressDebutJson,16)==int(previous_maxbound,16)):
                    within_range = True
                else:
                    while (int(adressDebutJson,16)<int(previous_maxbound,16)):
                        iterator+=1
                        previous_maxbound = adressFinJson
                        previous_minbound = adressDebutJson
                        adressDebutJson = objects[iterator]['minbound']
                        adressFinJson = objects[iterator]['maxbound']
        if within_range:
            selected_lines.append(line)
    writeInXMLfile(xmlDestiationFile,functionXMLelements)
# #############################
# This function allows for the recovery of variable declarations, function arguments, and return variables (data flow logic)
def recupererVariables(lines, nb_para):
    # STEPS:
    # 1: Parse lines as strigs
    # 2: For every string get : adress, opcode, other
    # 3: Check if opcode is a memory or stack manipulation : STUR, LDR, STR, MOV, STP, LDP. then for every case do something
    # 4: It must return a struture that contain all variables and the address where to insert this ones, and liste of arguments for functions calls
    
    markedRegisters = []
    variables = {}
    Index = {}
    iterateurNomVariable = 0
    iterateurLignes = 0
    compt_para = 0
    boolMarqueurArguments = False
    listeArguments = {}
    arguments = []
    arguments_set = set()  # Track unique arguments to avoid duplicates
    retour = {}
    for line in lines:
        parts = line.strip().split('\t')
        match parts[1]:
            # destination mean assigned Register
            # source mean sourced register
            # recover the registry according to the instruction

            case "stp":
                if (compt_para!=nb_para):
                    
                    destination = parts[2].strip().split(';')[0].strip().split(',',2)[2]
                    nomParam = "Para_" + str(compt_para)

                    variables[parts[0]] = createVariableObject(nomParam, "") # source not important here
                    markedRegisters.append(destination) # Juste pour fait la recherche dans ces boucles
                    Index[destination] = nomParam

                    compt_para = compt_para + 1
            case "stur" | "str":
                source, destination = parts[2].strip().split(';')[0].strip().split(',',1)
                if checkIfImmediate(source):
                    pass
                else:
                    if (destination in markedRegisters) and (source in markedRegisters):
                        variables[parts[0]] = createVariableObject(Index[destination], Index[source])
                    elif destination in markedRegisters:
                        nomVariableSource = "Var_"+str(iterateurNomVariable)
                        iterateurNomVariable+=1

                        variables[parts[0]] = createVariableObject(Index[destination], nomVariableSource)

                        markedRegisters.append(source) # sauvegarde de registre
                        Index[source] = nomVariableSource
                    elif source in markedRegisters:
                        nomVariableDestination = "Var_"+str(iterateurNomVariable)
                        iterateurNomVariable+=1

                        variables[parts[0]] = createVariableObject(nomVariableDestination, Index[source])

                        markedRegisters.append(destination)
                        Index[destination] = nomVariableDestination
                    else:
                        nomVariableDestination = "Var_"+str(iterateurNomVariable)
                        iterateurNomVariable+=1
                        nomVariableSource = "Var_"+str(iterateurNomVariable)
                        iterateurNomVariable+=1

                        variables[parts[0]] = createVariableObject(nomVariableDestination, nomVariableSource)

                        markedRegisters.append(destination) # Juste pour fait la recherche dans ces boucles
                        Index[destination] = nomVariableDestination # Juste pour naviguer directement (apres je peut optimiser)
                        markedRegisters.append(source) # sauvegarde de registre
                        Index[source] = nomVariableSource

                    if boolMarqueurArguments:
                        if destination in registresArguments and nomVariableSource not in arguments_set:
                            arguments.append(nomVariableSource)
                            arguments_set.add(nomVariableSource)
                        else:
                            arguments = []
                            arguments_set.clear()
                            boolMarqueurArguments = False
                    else:
                        if destination in registresArguments:
                            boolMarqueurArguments = True
                            if nomVariableSource not in arguments_set:
                                arguments.append(nomVariableSource)
                                arguments_set.add(nomVariableSource)
            case "ldr":
                destination, source = parts[2].strip().split(';')[0].strip().split(',',1)
                if (destination in markedRegisters) and (source in markedRegisters):
                    variables[parts[0]] = createVariableObject(Index[destination], Index[source])
                elif destination in markedRegisters:
                    nomVariableSource = "Var_"+str(iterateurNomVariable)
                    iterateurNomVariable+=1
                    
                    variables[parts[0]] = createVariableObject(Index[destination], nomVariableSource)

                    markedRegisters.append(source) # sauvegarde de registre
                    Index[source] = nomVariableSource
                elif source in markedRegisters:
                    nomVariableDestination = "Var_"+str(iterateurNomVariable)
                    iterateurNomVariable+=1

                    variables[parts[0]] = createVariableObject(nomVariableDestination, Index[source])

                    markedRegisters.append(destination)
                    Index[destination] = nomVariableDestination
                else:
                    nomVariableDestination = "Var_"+str(iterateurNomVariable)
                    iterateurNomVariable+=1
                    nomVariableSource = "Var_"+str(iterateurNomVariable)
                    iterateurNomVariable+=1
                    
                    variables[parts[0]] = createVariableObject(nomVariableDestination, nomVariableSource)
                    
                    markedRegisters.append(destination) # Juste pour fait la recherche dans ces boucles
                    Index[destination] = nomVariableDestination # Juste pour naviguer directement (apres je peut optimiser)
                    markedRegisters.append(source) # sauvegarde de registre
                    Index[source] = nomVariableSource
                
                if boolMarqueurArguments:
                    if destination in registresArguments and nomVariableSource not in arguments_set:
                        arguments.append(nomVariableSource)
                        arguments_set.add(nomVariableSource)
                    else:
                        arguments = []
                        arguments_set.clear()
                        boolMarqueurArguments = False
                else:
                    if destination in registresArguments:
                        boolMarqueurArguments = True
                        if nomVariableSource not in arguments_set:
                            arguments.append(nomVariableSource)
                            arguments_set.add(nomVariableSource)
            case "mov":
                destination, source = parts[2].strip().split(';')[0].strip().split(',')
                if checkIfImmediate(source) or (destination == source):
                    pass
                else:
                    if (destination in markedRegisters) and (source in markedRegisters):
                        variables[parts[0]] = createVariableObject(Index[destination], Index[source])
                    elif destination in markedRegisters:
                        nomVariableSource = "Var_"+str(iterateurNomVariable)
                        iterateurNomVariable+=1

                        variables[parts[0]] = createVariableObject(Index[destination], nomVariableSource)

                        markedRegisters.append(source) # sauvegarde de registre
                        Index[source] = nomVariableSource
                    elif source in markedRegisters:
                        nomVariableDestination = "Var_"+str(iterateurNomVariable)
                        iterateurNomVariable+=1

                        variables[parts[0]] = createVariableObject(nomVariableDestination, Index[source])

                        markedRegisters.append(destination)
                        Index[destination] = nomVariableDestination
                    else:
                        nomVariableDestination = "Var_"+str(iterateurNomVariable)
                        iterateurNomVariable+=1
                        nomVariableSource = "Var_"+str(iterateurNomVariable)
                        iterateurNomVariable+=1

                        variables[parts[0]] = createVariableObject(nomVariableDestination, nomVariableSource)

                        markedRegisters.append(destination) # Juste pour fait la recherche dans ces boucles
                        Index[destination] = nomVariableDestination # Juste pour naviguer directement (apres je peut optimiser)
                        markedRegisters.append(source) # sauvegarde de registre
                        Index[source] = nomVariableSource
                    
                    if boolMarqueurArguments:
                        if destination in registresArguments and nomVariableSource not in arguments_set:
                            arguments.append(nomVariableSource)
                            arguments_set.add(nomVariableSource)
                        else:
                            arguments = []
                            arguments_set.clear()
                            boolMarqueurArguments = False
                    else:
                        if destination in registresArguments:
                            boolMarqueurArguments = True
                            if nomVariableSource not in arguments_set:
                                arguments.append(nomVariableSource)
                                arguments_set.add(nomVariableSource)
            case "bl":
                if boolMarqueurArguments:
                    listeArguments[parts[0]] = arguments
                    arguments = []
                    arguments_set.clear()
                    boolMarqueurArguments = False
                pattern = r'(?P<address>[0-9a-fA-F]+)\s+(?P<mnemonic>\w+)(?:\s+(?P<operands>.+?))?(?:\s+;\s*(?P<info>.+))?$'
                if (len(lines) != (iterateurLignes+1)):
                    match = re.match(pattern, lines[iterateurLignes+1])
                    if match:
                        address = match.group('address')
                        mnemonic = match.group('mnemonic')
                        operands = match.group('operands')
                        if (mnemonic=="mov"):
                            if (operands.split(', ')[1]=="x0"):
                                retour[parts[0]] = address
                        if (mnemonic=="str" or mnemonic=="stur"):
                            if (operands.split(', ')[0]=="x0"):
                                retour[parts[0]] = address

            case _:
                if boolMarqueurArguments:
                    arguments = []
                    arguments_set.clear()
                    boolMarqueurArguments = False
        
        iterateurLignes = iterateurLignes + 1
    return variables, listeArguments, retour
# #############################
# This function separates functions into blocks and then recovers control flow logic
def separateFunction2Blocks(lines,minbound,maxbound,variables):
    # Explaining parsed instructions:
    # CBZ Rn, label : Compare and Branch on Zero : branch if Rn == 0
    # CBNZ Rn, label : Compare and Branch on Nonzero : branch if Rn != 0
    # TBZ Rn, #imm, label : Test bit and Branch if Zero : branch if ((the bit number imm in Rn) == 0)
    # TBNZ Rn, #imm, label : Test bit and Branch if Nonzero : branch if ((the bit number imm in Rn) != 0)
    control_flow = {}
    branch_addresses = set()
    branch_following_addresses = set()
    for ii in range(len(lines)):
        next_address = "0"
        parts = lines[ii].strip().split('\t')
        if len(parts) < 2:
            continue  # Skip lines with less than two parts : nop operations ex: @@@@@@ nop
        # parts[0] : address
        # parts[1] : opcode ex: mov
        # parts[2] : rest/operands
        mnemonic = parts[1]
        if ii < len(lines) - 1:
            next_address = lines[ii + 1].strip().split('\t')[0]
        adressActuelle = parts[0]
        # distinct between one argument instructions and multiple arguments instructions
        if (mnemonic.startswith('b.') or (mnemonic == "b")): # One argument
            if (next_address != "0"):
                branch_addresses.add(next_address)  # Address of the next line
            if not parts[2].startswith('0x'):
                # there is no target address in the instruction
                continue
            target_address = parts[2].replace('0x', '').split(' ;')[0]  # Remove '0x' prefix
            if (int(target_address,16)>=minbound and int(target_address,16)<=maxbound):
                branch_following_addresses.add(target_address)
            match mnemonic:
                case "b":
                    control_flow[adressActuelle] = create_incondition_object(target_address)
                case "b.eq":
                    control_flow[adressActuelle] = create_condition_object("Z=1", target_address, next_address)
                case "b.ne":
                    control_flow[adressActuelle] = create_condition_object("Z=0", target_address, next_address)
                case "b.cs"|"b.hs":
                    control_flow[adressActuelle] = create_condition_object("C=1", target_address, next_address)
                case "b.cc"|"b.lo":
                    control_flow[adressActuelle] = create_condition_object("C=0", target_address, next_address)
                case "b.mi":
                    control_flow[adressActuelle] = create_condition_object("N=1", target_address, next_address)
                case "b.pl":
                    control_flow[adressActuelle] = create_condition_object("N=0", target_address, next_address)
                case "b.vs":
                    control_flow[adressActuelle] = create_condition_object("V=1", target_address, next_address)
                case "b.vc":
                    control_flow[adressActuelle] = create_condition_object("V=0", target_address, next_address)
                case "b.hi":
                    control_flow[adressActuelle] = create_condition_object("C=1 & Z=0", target_address, next_address)
                case "b.ls":
                    control_flow[adressActuelle] = create_condition_object("C=0 & Z=1", target_address, next_address)
                case "b.ge":
                    control_flow[adressActuelle] = create_condition_object("N=V", target_address, next_address)
                case "b.lt":
                    control_flow[adressActuelle] = create_condition_object("N!=V", target_address, next_address)
                case "b.gt":
                    control_flow[adressActuelle] = create_condition_object("Z=0 & N=V", target_address, next_address)
                case "b.le":
                    control_flow[adressActuelle] = create_condition_object("Z=1 | N!=V", target_address, next_address)
                case "b.al":
                    control_flow[adressActuelle] = create_condition_object("true", target_address, next_address)
        else:
            if (mnemonic == "cbz" or mnemonic == "cbnz"): # Two arguments
                if (next_address != "0"):
                    branch_addresses.add(next_address)  # Address of the next line
                operands = parts[2].strip().split(', ')
                # example : @ cbz x12, 0x1320990
                if not operands[1].startswith('0x'):
                    # there is no target address in the instruction
                    continue
                target_address = operands[1].replace('0x', '')  # Remove '0x' prefix
                if (int(target_address,16)>=minbound and int(target_address,16)<=maxbound):
                    branch_following_addresses.add(target_address)
                match mnemonic:
                    case "cbz":
                        control_flow[adressActuelle] = create_condition_object(operands[0]+"=0", target_address, next_address)
                    case "cbnz":
                        control_flow[adressActuelle] = create_condition_object(operands[0]+"=0", next_address, target_address)
            else:
                if (mnemonic == "tbz" or mnemonic == "tbnz"): # Three arguments
                    if (next_address != "0"):
                        branch_addresses.add(next_address)  # Address of the next line
                    operands = parts[2].strip().split(', ')
                    # example : @ tbz x12, #0, 0x1320990
                    if not operands[2].startswith('0x'):
                        # there is no target address in the instruction
                        continue
                    target_address = operands[2].replace('0x', '')  # Remove '0x' prefix
                    if (int(target_address,16)>=minbound and int(target_address,16)<=maxbound):
                        branch_following_addresses.add(target_address)
                    match mnemonic:
                        case "tbz":
                            control_flow[adressActuelle] = create_condition_object(operands[0]+"["+operands[1].replace('#0x','')+"]=0", target_address, next_address)
                        case "tbnz":
                            control_flow[adressActuelle] = create_condition_object(operands[0]+"["+operands[1].replace('#0x','')+"]=0", next_address, target_address)

    # Block start addresses
    block_start_addresses = sorted(branch_addresses.union(branch_following_addresses))
    # Divide code into blocks
    blocks = []
    start_index = 0
    for i, addr in enumerate(block_start_addresses):
        try:
            end_index = lines.index(next(filter(lambda x: addr in x, lines[start_index:])), start_index)
        except Exception as e:
            # print(lines[start_index])
            pass
        block = lines[start_index:end_index ]
        if block!=[]:
            # check if there is "suite logique" in controle flow
            check_adress = block[-1].strip().split('\t')[0]
            if check_adress not in control_flow:
                suivante = lines[end_index].strip().split('\t')[0]
                control_flow[check_adress] = create_logique_object(suivante)
            adressDebut_newKey = block[0].strip().split('\t')[0]
            control_flow[adressDebut_newKey] = control_flow.pop(check_adress)
            blocks.append(block)
        start_index = end_index
    # Add the remaining code after the last block
    if start_index < len(lines):
        blocks.append(lines[start_index:])
    return blocks, control_flow
# #############################
# This function takes control and data flow, then combines them to construct the XML IR of a given function 
def constructXMLfunction(nomFonct, startAdress, blocks, control_flow, variables, listeArguments, retour):
    function = ET.Element("Function") # <Construct Function> Element
    function.set('id', startAdress) # ID attribute
    function.set('name', nomFonct) # Name attribute
    for block in blocks: # Construct blocks Elements
        block_XML = ET.Element("Block")
        id = block[0].strip().split('\t')[0]
        block_XML.set('id', id)
        block_XML = constructXMLbloc(block, variables, listeArguments, retour)
        # check if the bloc is not empty (it must have childrens)
        if len(block_XML) != 0:
            if (id in control_flow):
                controlFlow_XML = ET.Element("ControlFlow")
                match control_flow[id]["type"]:
                    case "suite_logique":
                        controlFlow_XML.set('type', "suite_logique")
                        controlFlow_XML.set('next', control_flow[id]["suivante"])
                    case "condition":
                        controlFlow_XML.set('type', "conditional")
                        controlFlow_XML.set('condition', control_flow[id]["condition"])
                        controlFlow_XML.set('true', control_flow[id]["true"])
                        controlFlow_XML.set('false', control_flow[id]["false"])
                    case "incondition":
                        controlFlow_XML.set('type', "inconditional")
                        controlFlow_XML.set('target', control_flow[id]["target"])
                block_XML.append(controlFlow_XML)
            function.append(block_XML)
    return function
# #############################
# This function takes data flow logic, then construct the XML IR of a given bloc 
def constructXMLbloc(block, variables, listeArguments, retour):
    block_XML = ET.Element("Block")
    id = block[0].strip().split('\t')[0]
    block_XML.set('id', id)
    iterator = 0 # ce iterateur est utilisé pour naviger dans les lignes du bloc
    pattern_for_function_name = r"; symbol stub for: (.+)$"
    pattern_for_function_name_message = r"; Objc message: (.+)$"
    pattern_for_literals_symbols = r";\s*literal pool symbol address:\s*(\S+)"
    for line in block:
        instruction_XML = None
        iterator+=1
        parts = line.strip().split('\t')
        match parts[1]:
            case "bl":
                match_1 = re.search(pattern_for_function_name, line)
                match_2 = re.search(pattern_for_function_name_message, line)
                if match_1:
                    nom_fonction = match_1.group(1)
                    if nom_fonction.startswith("_$") or nom_fonction.startswith("_T"):
                        nom_fonction = demangleSwift(nom_fonction)
                    else:
                        nom_fonction = demangleObjc(nom_fonction)
                    instruction_XML = ET.Element("Call")
                    instruction_XML.set('func', nom_fonction)
                    if (parts[0] in listeArguments):
                        for arg in listeArguments[parts[0]]:
                            arg_XML = ET.Element("Arg")
                            arg_XML.set('var', arg)
                            instruction_XML.append(arg_XML)
                    if (parts[0] in retour):
                        instruction_XML.set('return', variables[retour[parts[0]]]["nomVarDest"])
                else:
                    if match_2:
                        nom_fonction = match_2.group(1)
                        if nom_fonction.startswith("_$") or nom_fonction.startswith("_T"):
                            nom_fonction = demangleSwift(nom_fonction)
                        else:
                            nom_fonction = demangleObjc(nom_fonction)
                        instruction_XML = ET.Element("Call")
                        instruction_XML.set('func', nom_fonction)
                        if (parts[0] in listeArguments):
                            for arg in listeArguments[parts[0]]:
                                arg_XML = ET.Element("Arg")
                                arg_XML.set('var', arg)
                                instruction_XML.append(arg_XML)
                        if (parts[0] in retour):
                            instruction_XML.set('return', variables[retour[parts[0]]]["nomVarDest"])
                    else:
                        # there is only an adress
                        nom_fonction = parts[2]
                        instruction_XML = ET.Element("Call")
                        if nom_fonction.startswith("_$") or nom_fonction.startswith("_T"):
                            nom_fonction = demangleSwift(nom_fonction)
                        else:
                            nom_fonction = demangleObjc(nom_fonction)
                        instruction_XML.set('func', nom_fonction)
                        if (parts[0] in listeArguments):
                            for arg in listeArguments[parts[0]]:
                                arg_XML = ET.Element("Arg")
                                arg_XML.set('var', arg)
                                instruction_XML.append(arg_XML)
                        if (parts[0] in retour):
                            instruction_XML.set('return', variables[retour[parts[0]]]["nomVarDest"])
            case "b":
                match = re.search(pattern_for_function_name, line)
                if match:
                    nom_fonction = match.group(1)
            case "stp":
                # noter les parametres d'entré
                if parts[0] in variables:
                    instruction_XML = ET.Element("Parameter")
                    instruction_XML.set('name', variables[parts[0]]["nomVarDest"])
            case "ldr":
                match = re.search(pattern_for_literals_symbols, line)
                if match:
                    nom_litteral = match.group(1)
                    if nom_litteral.startswith("_$") or nom_litteral.startswith("_T"):
                        nom_litteral = demangleSwift(nom_litteral)
                    else:
                        nom_litteral = demangleObjc(nom_litteral)

                    instruction_XML = ET.Element("Litteral")
                    instruction_XML.set('name', nom_litteral)
                else:
                    instruction_XML = ET.Element("Assign")
                    instruction_XML.set('src', variables[parts[0]]["nomVarSrc"])
                    instruction_XML.set('dest', variables[parts[0]]["nomVarDest"])
            case "stur"|"str"|"mov":
                instruction_XML = ET.Element("Assign")
                instruction_XML.set('src', variables[parts[0]]["nomVarSrc"])
                instruction_XML.set('dest', variables[parts[0]]["nomVarDest"])
        if instruction_XML != None:
            block_XML.append(instruction_XML)
    return block_XML
# #############################
# This function writes XML content to a file
def writeInXMLfile(file_path, functionXMLelements):
    program = ET.Element("Program")
    tree = ET.ElementTree(program)
    root = tree.getroot()
    for function in functionXMLelements:
        root.append(function)
    # Convert the XML tree to a formatted string
    xml_str = ET.tostring(root, encoding='utf-8')
    formatted_xml = xml.dom.minidom.parseString(xml_str).toprettyxml(indent="  ")
    # Write the formatted XML to the file
    with open(file_path, "w") as f:
        f.write(formatted_xml)
# #############################
# This is the main function that launches the transformation of binary to IR
def transformBinaryToIR(disassemblyFilePath, jsonDestinationFilePath, xmlDestiationFile):
    with open(disassemblyFilePath, 'r') as file:
        lines = file.readlines()
        objects = readJsonObjects(jsonDestinationFilePath)
        if objects:
            selectLinesAndProcessTransformationToRI(lines, objects, xmlDestiationFile)
# #############################

def main(binaryFilePath, disassemblyFilePath, xmlDestinationFilePath):

    if (os.path.exists(binaryFilePath) and os.path.exists(disassemblyFilePath)):
        binaryName = getFileNameFromPath(binaryFilePath)

        jsonDestinationFilePath = "infos_"+binaryName+".json"
        getInfoCommand = f'r2 -e bin.cache=true -qc "aas;aflj > {jsonDestinationFilePath}" "{binaryFilePath}"'
        executeCommand(getInfoCommand)

        disassemblyFilePath = filterDisassembly(disassemblyFilePath)
        filterJsonInfos(jsonDestinationFilePath)
        keepOnlyDisassembledFunctions(disassemblyFilePath, jsonDestinationFilePath)

        transformBinaryToIR(disassemblyFilePath, jsonDestinationFilePath, xmlDestinationFilePath)
        os.remove(jsonDestinationFilePath)
        os.remove(disassemblyFilePath)