import os
import re
import json

def find_ip_addresses(text):
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b'
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?::\d{1,5})?\b'
    ip_pattern = f'({ipv4_pattern})|({ipv6_pattern})'
    matches = re.findall(ip_pattern, text)
    return [ip for ip_tuple in matches for ip in ip_tuple if ip]

def find_links(text):
    link_pattern = r'\b((?:https?://)?(?:(?:www\.)?(?:[\da-z\.-]+)\.(?:[a-z]{2,6})|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])))(?::[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])?(?:/[\w\.-]*)*/?)\b'
    return re.findall(link_pattern, text)

def find_emails(text):
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    return re.findall(email_pattern, text)

def regexFile(filePath):
    try:
        with open(filePath, 'r', encoding='utf-8') as file:
            pseudoCodeText = file.read()
        ip_addresses = list(set(find_ip_addresses(pseudoCodeText)))
        links = list(set(find_links(pseudoCodeText)))
        emails = list(set(find_emails(pseudoCodeText)))
        filename = os.path.splitext(os.path.basename(filePath))[0]
        fileResult = {
            filename: {
                'Adresses IP': ip_addresses,
                'Liens': links,
                'Adresses e-mail': emails
            }
        }
        return fileResult
    except FileNotFoundError:
        print(f"File not found: {filePath}")
        return None

def regexDirectoryFiles(directoryPath, jsonFilePath, filesEntries):
    if not os.path.isdir(directoryPath):
        print(f"Error: {directoryPath} is not a valid directory.")
        return
    textFiles = [f for f in os.listdir(directoryPath) if (f.endswith('.txt') and f.replace('.txt','') in filesEntries)]
    if not textFiles:
        print(f"No text files found in the directory: {directoryPath}")
        return
    # Créer un dictionnaire pour stocker les résultats de tous les fichiers
    allResults = {}
    for textFile in textFiles:
        filePath = os.path.join(directoryPath, textFile)
        result = regexFile(filePath)
        if result:
            # Fusionner les dictionnaires
            allResults.update(result)
    # Enregistrer les résultats dans un fichier JSON
    with open(jsonFilePath, 'w') as jsonFile:
        json.dump(allResults, jsonFile, indent=2)