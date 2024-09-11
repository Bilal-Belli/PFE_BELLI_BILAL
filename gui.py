import os, subprocess, threading, json
import xml.etree.ElementTree as ET
import tkinter as tk
import validators

from tkinter import filedialog
from regexAnalysis import regexDirectoryFiles
from transformationIR import main
from taintAnalysis import taintAnalysisMain
from extractBinaries import extractBinaryFile

# Variables Globales
    # selectedDirectory
    # NumbreOfFiles
    # filesEntries

# Pour changer dans l'interface graphique
def makeTextReadonly():
    textarea.config(state=tk.DISABLED)

# Pour changer dans l'interface graphique
def makeTextEditable():
    textarea.config(state=tk.NORMAL)

# Demande le lien vers le répertoire qui contient les fichiers MachO de test
def askDirectory():
    global selectedDirectory
    global NumbreOfFiles
    global filesEntries
    selectedDirectory = filedialog.askdirectory()
    if selectedDirectory:
        directory_var.set(selectedDirectory)
        # récupération des executables
        entries = os.listdir(selectedDirectory)
        filesEntries = [entry for entry in entries if os.path.isfile(os.path.join(selectedDirectory, entry))]  # Filtrer uniquement les fichiers .ipa
        for fileInDirectory in filesEntries:
            fileFullName = selectedDirectory+"/"+fileInDirectory
            extractBinaryFile(fileFullName)

        # Obtenir la liste des fichiers executables extraits avec success
        entries = os.listdir(selectedDirectory)
        filesEntries = [entry for entry in entries if os.path.isfile(os.path.join(selectedDirectory, entry))]  # Recensement pour une deusieme fois

        NumbreOfFiles = len(filesEntries) 
        makeTextEditable()
        textarea.insert(tk.END, f"Nombre de Fichiers: {NumbreOfFiles}\n")
        makeTextReadonly()

# pour la création d'un répertoire
def createDirectory(path, directoryName):
    fullPath = os.path.join(path, directoryName)
    if not os.path.exists(fullPath):
        os.makedirs(fullPath)

# pour exécuter une commande 
def executeCommand(command):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        output, error = process.communicate()
        return output, error
    except Exception as e:
        return None, str(e)

# pour garder que les informations utiles
def keepNecessaryInformations(inputJSON,outputTXT):
    with open(inputJSON, 'r', encoding='utf-8') as file:
        data = json.load(file)
    strings = [item['string'] for item in data if 'string' in item]
    with open(outputTXT, 'w', encoding='utf-8') as file:
        for string in strings:
            file.write(string + '\n')
    os.remove(inputJSON)

# Cette fonction permet de tirer toutes les chaines de caractères depuis le segment __Text du fichier MachO (sans decompilation)
def getStrings():
    createDirectory(selectedDirectory,"string")
    for file in filesEntries:
        filePath = os.path.join(selectedDirectory, file)
        destinationFilePath = os.path.join(selectedDirectory,"string", file)
        getStringCommand = f'r2 -e bin.cache=true -qc "izzj > {destinationFilePath}.json" "{filePath}"'
        output, error = executeCommand(getStringCommand)
        if error:
            print(f"Error analyzing {file} when getting strings: {error}")
            continue
        inputJSON = destinationFilePath+".json"
        outputJSON = destinationFilePath+".txt"
        keepNecessaryInformations(inputJSON, outputJSON)

# cette fonction utilise un autre script regexAnalysis.py, traverse la décompilation et applique des expressions régulières pour extraire les informations
def analyseStrings():
    createDirectory(selectedDirectory,"analysis")
    regexDirectoryFiles(os.path.join(selectedDirectory,"string"), os.path.join(selectedDirectory, "analysis", 'regexAnalysisResults.json'), filesEntries)

# cette fonction fait la transformation du code assembleur vers la representation intermédière (XML)
def decompilation():
    createDirectory(selectedDirectory,"decompilation")
    for file in filesEntries:
        filePath = os.path.join(selectedDirectory, file)
        # pour retrouver le fichier du code assembleur
        disassemblyFileName = file + ".txt"
        disassemblyFilePath = os.path.join(selectedDirectory, "disassembly", disassemblyFileName)
        # pour creer le fichier de RI
        xmlDestinationFileName = file + ".xml"
        xmlDestinationFilePath = os.path.join(selectedDirectory, "decompilation", xmlDestinationFileName)
        makeTextEditable()
        textarea.insert(tk.END, f"Décompilation de {file} (en cours)\n", "progress")
        makeTextReadonly()
        main(filePath, disassemblyFilePath, xmlDestinationFilePath)
        makeTextEditable()
        textarea.insert(tk.END, f"Décompilation de {file} (terminé)\n", "success")
        makeTextReadonly()

# l'application de l'analyse de contamunations
def analyseIR():
    allResults = {}
    jsonFilePath = os.path.join(selectedDirectory, "analysis", "taintAnalysisResults.json")
    for file in filesEntries:
        xmlDestinationFileName = file + ".xml"
        xmlDestinationFilePath = os.path.join(selectedDirectory, "decompilation", xmlDestinationFileName)
        result = taintAnalysisMain(xmlDestinationFilePath, file)
        # if result:
            # allResults[file] = result
        allResults[file] = result
    with open(jsonFilePath, 'w') as jsonFile:
        json.dump(allResults, jsonFile, indent=2)

# Cette fonction est le declencheur des opérations (Button "Analyser")
def launchAnalysis():
    makeTextEditable()
    textarea.insert(tk.END, f"Extraction des fichiers binaires\n", "progress")
    textarea.insert(tk.END, f"Extraction de chaînes (en cours)\n", "progress")
    makeTextReadonly()

    getStrings()

    makeTextEditable()
    textarea.insert(tk.END, f"Extraction de chaînes (terminé)\n", "success")
    textarea.insert(tk.END, f"Analyse des Addresses IP (en cours)\n", "progress")
    textarea.insert(tk.END, f"Analyse des liens (en cours)\n", "progress")
    makeTextReadonly()

    analyseStrings()

    makeTextEditable()
    textarea.insert(tk.END, f"Analyse des Addresses IP (terminé)\n", "success")
    textarea.insert(tk.END, f"Analyse des liens (terminé)\n", "success")
    textarea.insert(tk.END, f"Décompilation (en cours)\n", "progress")
    makeTextReadonly()

    decompilation()
    
    makeTextEditable()
    textarea.insert(tk.END, f"Décompilation (terminé)\n", "success")
    textarea.insert(tk.END, f"Analyse des fonctions, methodes (en cours)\n", "progress")
    makeTextReadonly()

    analyseIR()

    makeTextEditable()
    textarea.insert(tk.END, f"Analyse des fonctions, methodes (terminé)\n", "success")
    makeTextReadonly()

    generateReport()

    makeTextEditable()
    textarea.insert(tk.END, f"Rapport généré avec succès\n", "success")
    makeTextReadonly()

# fonctions multithreading
def onAnalyseButtonClick():
    analysis_thread = threading.Thread(target=launchAnalysis)
    analysis_thread.start()

def onShowReportButtonClick():
    show_thread = threading.Thread(target=showReport)
    show_thread.start()

# afficher le rapport de l'analyse
def showReport():
    try:
        filePath = os.path.join(selectedDirectory, "analysis", "REPORT.html")
        os.system(f"start {filePath}")
    except Exception as e:
        print(f"Error: {e}")

# générer le rapport en format HTML en utilisent les résutats de l'analyse (fichiers JSON)
def generateReport():
    with open(os.path.join(selectedDirectory, "analysis", "regexAnalysisResults.json"), 'r') as f:
        first_json = json.load(f)
    with open(os.path.join(selectedDirectory, "analysis", "taintAnalysisResults.json"), 'r') as f:
        second_json = json.load(f)
    with open(os.path.join(selectedDirectory, "analysis", "REPORT.html"), 'w') as f:
        f.write('<html>\n<head>\n<title>RAPPORT D\'ANALYSE</title>\n</head>\n<body>\n')
        for key in second_json:
            f.write(f'<h2>{key}</h2>\n')
            f.write('<table border="1">\n')
            f.write('<tr><th>Attribut</th><th>Valeurs</th></tr>\n')
            if key in second_json and isinstance(second_json[key], list):
                f.write('<tr><td>Résultats de l\'analyse des contaminations</td><td><ol>\n')
                if not second_json[key]:
                    f.write('<p style="color: green;">Aucun comportement malveillant détecté</p></ol></td></tr>\n')
                else:
                    for func_name in second_json[key]:
                        f.write(f'<li><p style="color: red;">{func_name}</p></li>\n')
                    f.write('</ol></td></tr>\n')
            for attribute, values in first_json[key].items():
                f.write(f'<tr><td>{attribute}</td><td><ul>\n')
                if attribute == "Liens":
                    for value in values:
                        if validators.url(value):
                            f.write(f'<li>{value}</li>\n')
                else:
                    for value in values:
                        f.write(f'<li>{value}</li>\n')
                f.write('</ul></td></tr>\n')
            f.write('</table>\n')
        f.write('</body>\n</html>')

# Créer la fenêtre principale
root = tk.Tk()
root.title("Analyseur")
root.geometry("500x250")

# Centrer la fenêtre sur l'écran
app_width = 550
app_height = 285
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = (screen_width / 2) - (app_width / 2)
y = (screen_height / 2 ) - (app_height / 2)
root.geometry(f'{app_width}x{app_height}+{int(x)}+{int(y)}')

# Rendre la fenêtre non redimensionnable
root.resizable(False, False)
root.iconbitmap("logo.ico")

# Variable pour stocker le répertoire sélectionné
directory_var = tk.StringVar()

directory_button = tk.Button(root, text="Sélectionner un dossier 🗀", command=askDirectory)
directory_button.grid(row=0, column=0, pady=1)

directory_entry = tk.Entry(root, textvariable=directory_var, state="readonly", width=60)
directory_entry.grid(row=0, column=1, pady=1)

Analyse_button = tk.Button(root, text="Analyser", command=onAnalyseButtonClick) # pour utiliser les threads
Analyse_button.grid(row=1, column=0, pady=1)

showReport_button = tk.Button(root, text="Afficher le Rapport", command=onShowReportButtonClick) # pour utiliser les threads
showReport_button.grid(row=1, column=1, pady=1)

textarea = tk.Text(root, width=60, state=tk.DISABLED)
textarea.grid(row=2, column=0, columnspan=2, pady=5, padx=1, sticky="nsew")
textarea.tag_configure("progress", foreground="blue")
textarea.tag_configure("danger", foreground="red")
textarea.tag_configure("information", foreground="black")
textarea.tag_configure("success", foreground="green")
# Configurer les poids des lignes et des colonnes pour rendre la zone de texte extensible
root.grid_rowconfigure(2, weight=1)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)

# Démarrer la boucle d'événements Tkinter
root.mainloop()