import os
import re
import json

def find_ip_addresses(text):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?::\d{1,5})?\b'
    return re.findall(ip_pattern, text)

def find_links(text):
    link_pattern = r'\bhttps?://\S+\b'
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
                'IP Addresses': ip_addresses,
                'Links': links,
                'Emails': emails
            }
        }
        return fileResult
    except FileNotFoundError:
        print(f"File not found: {filePath}")
        return None

def regexDirectoryFiles(directoryPath, jsonFilePath):
    if not os.path.isdir(directoryPath):
        print(f"Error: {directoryPath} is not a valid directory.")
        return
    textFiles = [f for f in os.listdir(directoryPath) if f.endswith('.txt')]
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