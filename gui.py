import os, subprocess, threading, json
import xml.etree.ElementTree as ET
import tkinter as tk

from tkinter import filedialog
from regexAnalysis import regexDirectoryFiles
from transformationIR import main
from taintAnalysis import taintAnalysisMain

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
        # Obtenir la liste des fichiers et des répertoires dans le chemin sélectionné
        entries = os.listdir(selectedDirectory)
        filesEntries = [entry for entry in entries if os.path.isfile(os.path.join(selectedDirectory, entry))]  # Filtrer uniquement les fichiers
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
    regexDirectoryFiles(os.path.join(selectedDirectory,"string"), os.path.join(selectedDirectory, "analysis", 'regexAnalysisResults.json'))

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
        main(filePath, disassemblyFilePath, xmlDestinationFilePath)

# l'application de l'analyse de contamunations
def analyseIR():
    allResults = {}
    jsonFilePath = os.path.join(selectedDirectory, "analysis", "taintAnalysisResults.json")
    for file in filesEntries:
        xmlDestinationFileName = file + ".xml"
        xmlDestinationFilePath = os.path.join(selectedDirectory, "decompilation", xmlDestinationFileName)
        result = taintAnalysisMain(xmlDestinationFilePath, file)
        if result:
            allResults.update(result)
    with open(jsonFilePath, 'w') as jsonFile:
        json.dump(allResults, jsonFile, indent=2)

# cette fonction sera utiliser pour compter le nombre d'occurences des elements du vecteur fonctions sencibles
def countVectorOccurrencesForXML(array, filePath):
    count = 0
    names_found = set()  # pour garder une trace des noms trouvés dans le fichier
    tree = ET.parse(filePath)
    root = tree.getroot()
    # Parcourez toutes les balises <Call> et obtenez l'attribut « func »
    for call in root.iter('Call'):
        func_name = call.get('func')
        if func_name and func_name in array and func_name not in names_found:
            count += 1
            names_found.add(func_name)
    return count

# analyse si il existe beaucoup de fonctions sencibles qui tentent d'avoir un maximum des informations
def analyseMethods():
    suspectFunctionsArray = ["UITextField","UITextView","UIDocumentPickerViewController","documentPicker","imagePickerController", "pickerView","dataTask","Alamofire","request","contents","contentsOfDirectory","stringWithContentsOfURL:encoding","initWithContentsOfFile:encoding:error:", "fork", 
    "contentsOfDirectory","contents","NotificationCenter","addObserver","CoreLocation","locationManager", "UIAlertController","Pasteboard","UIPasteboard.general.string","NSManagedObjectContext","existingObject","AVCapture","AVCaptureVideoDataOutput","captureOutput","AVCaptureAudioDataOutput",
    "Realm.write","UIApplication","evaluateJavaScript","UserDefaults","UITextField","placeholder","UITextView","text","attributedText","UIDatePicker","date","UIAlertView","textFieldAtIndex:","UIPickerView","selectedRowInComponent:","initWithContentsOfURL:encoding","Realm.objects", "popen", 
    "titleForRow:forComponent","NSFileManager","contentsAtPath:","contentsOfDirectoryAtPath:error","fileExistsAtPath","NSData","dataWithContentsOfFile","dataWithContentsOfURL:","initWithContentsOfFile:", "initWithContentsOfURL","NSString","stringWithContentsOfFile:encoding", "dlsym", "system",
    "NSURLSession","dataTaskWithURL:","dataTaskWithRequest","downloadTaskWithURL","downloadTaskWithRequest:","NSURLConnection","sendAsynchronousRequest:queue:completionHandler", "sendSynchronousRequest:returningResponse","NSStream","inputStreamWithURL","UIPasteboard","NSManagedObjectContext",
    "GET:parameters:success:failure:","POST:parameters:success:failure","PUT:parameters:success:failure","DELETE:parameters:success:failure","NSUserDefaults","objectForKey","stringForKey", "arrayForKey","dictionaryForKey","dataForKey:","SecItemCopyMatching","SecItemAdd","SecItemUpdate","Clipboard",
    "executeFetchRequest:error:","fetchRequestFromTemplateWithName:substitutionVariables","FMDB","executeQuery","executeQuery:withArgumentsInArray:","NSNotificationCenter","addObserver:selector:name:object:","addObserverForName:object:queue:usingBlock","NSNotification","userInfo","UIApplication",
    "NSProcessInfo","environment","arguments","UIDevice","name","model","systemName","systemVersion","CLLocationManager","location","startUpdatingLocation","startMonitoringSignificantLocationChanges","inputStreamWithFileAtPath","initWithURL","initWithFileAtPath","AFNetworking","objc_msgSend",  
    "requestLocation","requestWhenInUseAuthorization","requestAlwaysAuthorization","UIImagePickerController","delegate","sourceType","mediaTypes","allowsEditing","AVCaptureDevice","devices","defaultDeviceWithMediaType","set", "setPersistentDomain", "FileManager.createFile", "objc_msgSendSuper",
    "FileManager.removeItem", "FileManager.contents", "SecItemAdd", "SecItemUpdate", "SecItemCopyMatching", "SecItemDelete", "URLSession.dataTask","AVAudioPlayer.play","NSXPCConnection.synchronousRemoteObjectProxy", "NSXPCConnection.exportedObject","FileManager.copyItem", "FileManager.moveItem",
    "URLSession.uploadTask", "URLSession.downloadTask", "URLSession.streamTask", "URLSessionWebSocketTask.send", "URLSessionWebSocketTask.receive", "FileHandle.readDataToEndOfFile", "FileHandle.readData", "FileHandle.write", "FileHandle.seek", "NSXPCConnection.remoteObjectProxy",  "dlopen", 
    "NSXPCConnection.exportedInterface", "UIAlertController", "UIAlertController.init", "UIAlertAction.init", "CCCrypt", "CCCryptorCreate", "CCCryptorUpdate", "CCCryptorFinal", "CryptoKit", "SHA256.hash", "SHA512.hash", "AES.GCM.seal", "AES.GCM.open", "CoreData", "NSManagedObjectContext.save", 
    "NSManagedObjectContext.fetch", "NSManagedObjectContext.delete", "NSPersistentContainer.loadPersistentStores", "sqlite3_exec", "sqlite3_prepare_v2", "sqlite3_step", "sqlite3_finalize", "WKWebView.load", "WKWebView.loadHTMLString", "WKWebView.loadFileURL", "UNUserNotificationCenter.add", 
    "UNUserNotificationCenter.removePendingNotificationRequests", "UNUserNotificationCenter.removeDeliveredNotifications", "UIPasteboard.general.setItems", "openURL:","canOpenURL:","NSOpenPanel","URLs","beginWithCompletionHandler","NSURLConnection sendAsynchronousRequest:queue:completionHandler:",
    "UIPasteboard.general.setValue", "UIPasteboard.general.setString", "UIPasteboard.general.string", "CLLocationManager.startUpdatingLocation", "CLLocationManager.stopUpdatingLocation", "CLLocationManager.requestWhenInUseAuthorization", "CLLocationManager.requestAlwaysAuthorization", 
    "AVAudioRecorder.record", "AVCaptureSession.startRunning", "AVCaptureSession.stopRunning", "NSURLSession", "NSURLRequest", "NSURLConnection", "CFNetwork", "+[NSStream getStreamsToHostWithName:port:inputStream:outputStream:]","UIAlertView", "UIActionSheet", "UIPasteboard","NSURLSessionDownloadTask",
    "+[NSURLConnection sendSynchronousRequest:returningResponse:error:]", "+[NSURLConnection connectionWithRequest:delegate:]", "-[NSData initWithContentsOfFile:]", "-[NSString initWithContentsOfFile:]","exec", "CCCrypt", "SecKeyEncrypt", "SecKeyDecrypt", "SecItemAdd", "SecItemUpdate", 
    "-[NSDictionary initWithContentsOfFile:]", "-[NSArray initWithContentsOfFile:]", "-[NSFileManager createFileAtPath:contents:attributes:]", "-[NSFileManager copyItemAtPath:toPath:error:]",  "+[SAMKeychain setPasswordObject:forService:account:]","+[SAMKeychain setPasswordData:forService:account:]",
    "-[NSFileManager moveItemAtPath:toPath:error:]", "-[NSFileManager removeItemAtPath:error:]", "-[NSUserDefaults setObject:forKey:]", "-[NSUserDefaults setInteger:forKey:]", "-[NSUserDefaults setBool:forKey:]", "+[SAMKeychain setPassword:forService:account:]", "NSURLSessionUploadTask",  
    "-[UIApplication openURL:]", "-[UIApplication canOpenURL:]", "-[UIWebView loadRequest:]", "-[WKWebView loadRequest:]", "sqlite3_exec", "sqlite3_prepare_v2", "FMDatabase executeUpdate:", "FMDatabase executeQuery:","+[NSPropertyListSerialization dataWithPropertyList:format:options:error:]",
    "SecItemCopyMatching", "SecItemDelete", "NSLog", "printf", "fprintf", "CFShow", "NSURL URLWithString:", "NSURL fileURLWithPath:", "-[NSKeyedArchiver archivedDataWithRootObject:]", "+[NSJSONSerialization dataWithJSONObject:options:error:]","NSURLSessionDataTask", 
    "JSContext evaluateScript:", "-[JSContext evaluateScript:]", "-[WKWebView evaluateJavaScript:completionHandler:]", "UITextField text", "UITextView text", "-[UIWebView stringByEvaluatingJavaScriptFromString:]" ]
    folder_path = os.path.join(selectedDirectory, "decompilation")
    result = {}
    for filename in os.listdir(folder_path):
        if filename.endswith(".xml"):
            filePath = os.path.join(folder_path, filename)
            
            counts = countVectorOccurrencesForXML(suspectFunctionsArray, filePath)
            
            result[os.path.splitext(filename)[0]] = counts
    with open(os.path.join(selectedDirectory, "analysis", "functionsAnalysisResults.json"), 'w') as json_file:
        json.dump(result, json_file, indent=4)

# Cette fonction est le declencheur des opérations (Button "Analyser")
def launchAnalysis():
    makeTextEditable()
    textarea.insert(tk.END, f"Extraction de chaînes (en cours)\n", "progress")
    makeTextReadonly()

    getStrings()

    makeTextEditable()
    textarea.insert(tk.END, f"Extraction de chaînes (finie)\n", "success")
    textarea.insert(tk.END, f"Analyse des Addresses IP (en cours)\n", "progress")
    textarea.insert(tk.END, f"Analyse des liens (en cours)\n", "progress")
    makeTextReadonly()

    analyseStrings()

    makeTextEditable()
    textarea.insert(tk.END, f"Analyse des Addresses IP (finie)\n", "success")
    textarea.insert(tk.END, f"Analyse des liens (finie)\n", "success")
    textarea.insert(tk.END, f"Décompilation (en cours)\n", "progress")
    makeTextReadonly()

    decompilation()
    
    makeTextEditable()
    textarea.insert(tk.END, f"Décompilation (finie)\n", "success")
    textarea.insert(tk.END, f"Analyse des fonctions, methodes (en cours)\n", "progress")
    makeTextReadonly()

    analyseIR()
    analyseMethods()

    makeTextEditable()
    textarea.insert(tk.END, f"Analyse des fonctions, methodes (finie)\n", "success")
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
    with open(os.path.join(selectedDirectory, "analysis", "functionsAnalysisResults.json"), 'r') as f:
        third_json = json.load(f)
    with open(os.path.join(selectedDirectory, "analysis", "REPORT.html"), 'w') as f:
        f.write('<html>\n<head>\n<title>ANALYSIS REPORT</title>\n</head>\n<body>\n')
        for key in first_json:
            f.write(f'<h2>{key}</h2>\n')
            f.write('<table border="1">\n')
            f.write('<tr><th>Attribute</th><th>Value</th></tr>\n')
            for attribute, value in first_json[key].items():
                f.write(f'<tr><td>{attribute}</td><td>{value}</td></tr>\n')
            if key in second_json and isinstance(second_json[key], list):
                f.write('<tr><td>vulnerabilites</td><td><ul>\n')
                for func_name in second_json[key]:
                    f.write(f'<li>{func_name}</li>\n')
                f.write('</ul></td></tr>\n')
            if key in third_json:
                f.write(f'<tr><td>number_of_suspect_functions</td><td>{second_json[key]}</td></tr>\n')
            else:
                f.write('<tr><td>number_of_suspect_functions</td><td>0</td></tr>\n')
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

directory_button = tk.Button(root, text="Sélectionnez le répertoire 🗀", command=askDirectory)
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