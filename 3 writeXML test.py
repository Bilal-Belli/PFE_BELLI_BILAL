import xml.etree.ElementTree as ET
import xml.dom.minidom
import json
import re

registresArguments = ['w0','w1','w2','w3','w4','w5','w6','w7','x0','x1','x2','x3','x4','x5','x6','x7']

def createVariableObject(nomVariableDestination, nomVariableSource):
    return {
        "nomVarDest": nomVariableDestination,
        "nomVarSrc": nomVariableSource
    }

def create_condition_object(condition, true, false):
    return {
        "type": "condition",
        "condition": condition,
        "true": true,
        "false": false
    }

def create_incondition_object(target):
    return {
        "type": "incondition",
        "target": target,
    }

def create_logique_object(suivante):
    return {
        "type": "suite_logique",
        "suivante": suivante
    }

def checkIfImmediate(var):
    if str(var).startswith("#"):
        return True
    else:
        return False

def getNameAndNumberOfParametres(signature):
    splitedParts = signature.strip().split(' (')
    return splitedParts[0], len(splitedParts[1].replace(');', '').strip().split(', '))

def getJsonObjects(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        print(f"Json file not found!")
        return None

def selectLinesAndProcessTransformationToRI(lines, objects):
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
                variables, listeArguments = recupererVariables(selected_lines, nombreParametres)

                blocks, control_flow = separateFunction2Blocs(selected_lines, int(adressDebutJson, 16), int(adressFinJson, 16))
                functionXMLelements.append(constructXMLfunction(nomFonct, previous_minbound, blocks, control_flow, variables, listeArguments))
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
    writeInXMLfile("program.xml",functionXMLelements)

def recupererVariables(lines, nb_para):
    # Parse lines as strigs
    # For every string get : adress, opcode, other
    # Check if opcode is a memory or stack manipulation : STUR, LDR, STR, MOV, STP, LDP. then for every case do something
    # It must return a struture that contain all variables and the address where to insert this ones, and liste of arguments for functions calls
    
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
    for line in lines:
        parts = line.strip().split('\t')
        match parts[1]:
            # destination mean assigned Register
            # source mean sourced register
            # recuperer le registre selon l'instruction

            # case "adrp":
            #     destination = parts[2].strip().split(';')[0].strip().split(',')[0]
            #     source = parts[2].strip().split(';')[1]
            #     if destination in markedRegisters:
            #         nomVariableSource = "Var_"+str(iterateurNomVariable)
            #         iterateurNomVariable+=1
            #         variables[parts[0]] = createVariableObject(Index[destination], nomVariableSource)
            #         markedRegisters.append(source) # sauvegarde de registre
            #         Index[source] = nomVariableSource
            #     else:
            #         nomVariableDestination = "Var_"+str(iterateurNomVariable)
            #         iterateurNomVariable+=1
            #         nomVariableSource = "Var_"+str(iterateurNomVariable)
            #         iterateurNomVariable+=1
            #         variables[parts[0]] = createVariableObject(nomVariableDestination, nomVariableSource)
            #         markedRegisters.append(destination) # Juste pour fait la recherche dans ces boucles
            #         Index[destination] = nomVariableDestination # Juste pour naviguer directement (apres je peut optimiser)
            #         markedRegisters.append(source) # sauvegarde de registre
            #         Index[source] = nomVariableSource
            case "stp":
                if (compt_para!=nb_para):
                    
                    destination = parts[2].strip().split(';')[0].strip().split(',',2)[2]
                    nomParam = "Para_" + str(compt_para)

                    variables[parts[0]] = createVariableObject(nomParam, "") # source not important here
                    markedRegisters.append(destination) # Juste pour fait la recherche dans ces boucles
                    Index[destination] = nomParam

                    compt_para = compt_para + 1
            # case "ldp":

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
                # if (lines[iterateurLignes+1].strip().split('\t')[1] = "x0"):

            case _:
                if boolMarqueurArguments:
                    arguments = []
                    arguments_set.clear()
                    boolMarqueurArguments = False
        
        iterateurLignes = iterateurLignes + 1
    return variables, listeArguments

def separateFunction2Blocs(lines,minbound,maxbound):
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
            target_address = parts[2].replace('0x', '').split(' ;')[0]  # Remove '0x' prefix
            if (int(target_address,16)>=minbound and int(target_address,16)<=maxbound):
                branch_following_addresses.add(target_address)
            match mnemonic:
                case "b":
                    control_flow[adressActuelle] = create_incondition_object(target_address)
                case "b.eq":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.ne":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.cs":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.hs":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.cc":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.lo":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.mi":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.pl":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.vs":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.vc":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.hi":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.ls":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.ge":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.lt":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.gt":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.le":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
                case "b.al":
                    control_flow[adressActuelle] = create_condition_object("condition", target_address, next_address)
        else:
            if (mnemonic == "cbz" or mnemonic == "cbnz"): # Two arguments
                if (next_address != "0"):
                    branch_addresses.add(next_address)  # Address of the next line
                operands = parts[2].strip().split(', ')
                # example : @ cbz x12, 0x1320990
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

def constructXMLfunction(nomFonct, startAdress, blocks, control_flow, variables, listeArguments):
    # <Function> Element
    function = ET.Element("Function")
    function.set('id', startAdress) # ID attribute
    function.set('name', nomFonct) # Name attribute
    # Blocks Elements
    for block in blocks:
        block_XML = ET.Element("Block")
        id = block[0].strip().split('\t')[0]
        block_XML.set('id', id)
        block_XML = constructXMLbloc(block, variables, listeArguments)

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

def constructXMLbloc(block, variables, listeArguments):
    block_XML = ET.Element("Block")
    id = block[0].strip().split('\t')[0]
    block_XML.set('id', id)
    
    # ce iterateur est utilisé pour naviger dans les lignes du bloc
    iterator = 0
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
                    instruction_XML = ET.Element("Call")
                    instruction_XML.set('func', nom_fonction)
                    if (parts[0] in listeArguments):
                        for arg in listeArguments[parts[0]]:
                            arg_XML = ET.Element("Arg")
                            arg_XML.set('var', arg)
                            instruction_XML.append(arg_XML)
                else:
                    if match_2:
                        nom_fonction = match_2.group(1)
                        instruction_XML = ET.Element("Call")
                        instruction_XML.set('func', nom_fonction)
                        if (parts[0] in listeArguments):
                            for arg in listeArguments[parts[0]]:
                                arg_XML = ET.Element("Arg")
                                arg_XML.set('var', arg)
                                instruction_XML.append(arg_XML)
                    else:
                        # there is only an adress
                        nom_fonction = "sym.func."+parts[2]
                        instruction_XML = ET.Element("Call")
                        instruction_XML.set('func', nom_fonction)
                        if (parts[0] in listeArguments):
                            for arg in listeArguments[parts[0]]:
                                arg_XML = ET.Element("Arg")
                                arg_XML.set('var', arg)
                                instruction_XML.append(arg_XML)
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

file_path = 'filtered_output.txt'
json_file = 'infos_sidestore.json'

with open(file_path, 'r') as file:
    lines = file.readlines()
    objects = getJsonObjects(json_file)
    if objects:
        selectLinesAndProcessTransformationToRI(lines, objects)