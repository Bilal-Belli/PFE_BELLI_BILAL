import xml.etree.ElementTree as ET

# Input source functions
# inputFunctionsNamesSwift = {"UITextField","UITextView","UIDocumentPickerViewController","documentPicker(_:didPickDocumentsAt:)","imagePickerController(_:didFinishPickingMediaWithInfo:)",
#     "pickerView(_:didSelectRow:inComponent:)","dataTask(with:completionHandler:)","Alamofire (Third-party)","request(_:method:parameters:encoding:headers:)","contents(atPath:)","contentsOfDirectory(atPath:)",
#     "contentsOfDirectory(at:includingPropertiesForKeys:options:)","contents(at:)","NotificationCenter","addObserver(_:selector:name:object:)","CoreLocation","locationManager(_:didUpdateLocations:)",
#     "UIAlertController","object(forKey:)","string(forKey:)","array(forKey:)","dictionary(forKey:)","Pasteboard","UIPasteboard.general.string","NSManagedObjectContext","fetch(_:completionHandler:)",
#     "execute(_:)","existingObject(with:)","AVCapture","AVCaptureVideoDataOutput","captureOutput(_:didOutput:from:)","AVCaptureAudioDataOutput","captureOutput(_:didOutput:from:)","Realm().objects(_:)",
#     "Realm().write(_:)","UIApplication","open(_:options:completionHandler:)","load(_:dataMIMEType:textEncodingName:baseURL:)","evaluateJavaScript(_:completionHandler:)","UserDefaults","value(forKey:)",
#     "object(forKey:)","string(forKey:)"}
# inputFunctionsNamesObjc = {"UITextField","text","placeholder","UITextView","text","attributedText","UIDatePicker","date","UIAlertView","textFieldAtIndex:","UIPickerView","selectedRowInComponent:",
#     "titleForRow:forComponent:","NSFileManager","contentsAtPath:","contentsOfDirectoryAtPath:error:","fileExistsAtPath:","NSData","dataWithContentsOfFile:","dataWithContentsOfURL:","initWithContentsOfFile:",
#     "initWithContentsOfURL:","NSString","stringWithContentsOfFile:encoding:error:","stringWithContentsOfURL:encoding:error:","initWithContentsOfFile:encoding:error:","initWithContentsOfURL:encoding:error:",
#     "NSURLSession","dataTaskWithURL:","dataTaskWithRequest:","downloadTaskWithURL:","downloadTaskWithRequest:","NSURLConnection","sendAsynchronousRequest:queue:completionHandler:",
#     "sendSynchronousRequest:returningResponse:error:","NSStream","inputStreamWithURL:","inputStreamWithFileAtPath:","initWithURL:","initWithFileAtPath:","AFNetworking (Third-party library)",
#     "GET:parameters:success:failure:","POST:parameters:success:failure:","PUT:parameters:success:failure:","DELETE:parameters:success:failure:","NSUserDefaults","objectForKey:","stringForKey:",
#     "arrayForKey:","dictionaryForKey:","dataForKey:","SecItemCopyMatching","SecItemAdd","SecItemUpdate","Clipboard","UIPasteboard","string","strings","URL","URLs","image","images","NSManagedObjectContext",
#     "executeFetchRequest:error:","fetchRequestFromTemplateWithName:substitutionVariables:","FMDB (Third-party library)","executeQuery:","executeQuery:withArgumentsInArray:","NSNotificationCenter",
#     "addObserver:selector:name:object:","addObserverForName:object:queue:usingBlock:","NSNotification","userInfo","UIApplication","openURL:","canOpenURL:","NSOpenPanel (macOS)","URLs","beginWithCompletionHandler:",
#     "NSProcessInfo","environment","arguments","UIDevice","name","model","systemName","systemVersion","CLLocationManager","location","startUpdatingLocation","startMonitoringSignificantLocationChanges",
#     "requestLocation","requestWhenInUseAuthorization","requestAlwaysAuthorization","UIImagePickerController","delegate","sourceType","mediaTypes","allowsEditing","AVCaptureDevice","devices","defaultDeviceWithMediaType:"}
# Sensitive functions
# taintSinkFunctionsSwift = {"set(_:forKey:)", "setPersistentDomain(_:forName:)", "FileManager.createFile(atPath:contents:attributes:)", "FileManager.copyItem(at:to:)", "FileManager.moveItem(at:to:)",
#     "FileManager.removeItem(at:)", "FileManager.contents(atPath:)", "SecItemAdd(_:_:)", "SecItemUpdate(_:_:)", "SecItemCopyMatching(_:_:)", "SecItemDelete(_:)", "URLSession.dataTask(with:)",
#     "URLSession.uploadTask(with:from:)", "URLSession.downloadTask(with:)", "URLSession.streamTask(with:)", "URLSessionWebSocketTask.send(_:completionHandler:)", 
#     "URLSessionWebSocketTask.receive(completionHandler:)", "print(_:separator:terminator:)", "readLine(strippingNewline:)", "FileHandle.readDataToEndOfFile()", "FileHandle.readData(ofLength:)",
#     "FileHandle.write(_:)", "FileHandle.seek(toFileOffset:)", "NSXPCConnection.remoteObjectProxy", "NSXPCConnection.synchronousRemoteObjectProxy", "NSXPCConnection.exportedObject",
#     "NSXPCConnection.exportedInterface", "UIAlertController", "UIAlertController.init(title:message:preferredStyle:)", "UIAlertAction.init(title:style:handler:)", "CCCrypt", "CCCryptorCreate",
#     "CCCryptorUpdate", "CCCryptorFinal", "CryptoKit", "SHA256.hash(data:)", "SHA512.hash(data:)", "AES.GCM.seal(_:using:)", "AES.GCM.open(_:using:)", "CoreData", "NSManagedObjectContext.save()", 
#     "NSManagedObjectContext.fetch(_:)", "NSManagedObjectContext.delete(_:)", "NSPersistentContainer.loadPersistentStores(completionHandler:)", "sqlite3_exec", "sqlite3_prepare_v2", "sqlite3_step", 
#     "sqlite3_finalize", "WKWebView.load(_:)", "WKWebView.loadHTMLString(_:baseURL:)", "WKWebView.loadFileURL(_:allowingReadAccessTo:)", "UNUserNotificationCenter.add(_:withCompletionHandler:)", 
#     "UNUserNotificationCenter.removePendingNotificationRequests(withIdentifiers:)", "UNUserNotificationCenter.removeDeliveredNotifications(withIdentifiers:)", "UIPasteboard.general.setItems(_:options:)", 
#     "UIPasteboard.general.setValue(_:forPasteboardType:)", "UIPasteboard.general.setString(_:)", "UIPasteboard.general.string", "CLLocationManager.startUpdatingLocation()", 
#     "CLLocationManager.stopUpdatingLocation()", "CLLocationManager.requestWhenInUseAuthorization()", "CLLocationManager.requestAlwaysAuthorization()", "AVAudioPlayer.play()", 
#     "AVAudioRecorder.record()", "AVCaptureSession.startRunning()", "AVCaptureSession.stopRunning()"}
# taintSinkFunctionsObjc = {"NSURLSession", "NSURLRequest", "NSURLConnection", "CFNetwork", "+[NSStream getStreamsToHostWithName:port:inputStream:outputStream:]", 
#     "+[NSURLConnection sendSynchronousRequest:returningResponse:error:]", "+[NSURLConnection connectionWithRequest:delegate:]", "-[NSData initWithContentsOfFile:]", "-[NSString initWithContentsOfFile:]", 
#     "-[NSDictionary initWithContentsOfFile:]", "-[NSArray initWithContentsOfFile:]", "-[NSFileManager createFileAtPath:contents:attributes:]", "-[NSFileManager copyItemAtPath:toPath:error:]", 
#     "-[NSFileManager moveItemAtPath:toPath:error:]", "-[NSFileManager removeItemAtPath:error:]", "-[NSUserDefaults setObject:forKey:]", "-[NSUserDefaults setInteger:forKey:]", 
#     "-[NSUserDefaults setBool:forKey:]", "+[SAMKeychain setPassword:forService:account:]", "+[SAMKeychain setPasswordData:forService:account:]", "+[SAMKeychain setPasswordObject:forService:account:]", 
#     "-[UIApplication openURL:]", "-[UIApplication canOpenURL:]", "-[UIWebView loadRequest:]", "-[WKWebView loadRequest:]", "sqlite3_exec", "sqlite3_prepare_v2", "FMDatabase executeUpdate:", 
#     "FMDatabase executeQuery:", "objc_msgSend", "objc_msgSendSuper", "dlopen", "dlsym", "system", "popen", "fork", "exec", "CCCrypt", "SecKeyEncrypt", "SecKeyDecrypt", "SecItemAdd", "SecItemUpdate", 
#     "SecItemCopyMatching", "SecItemDelete", "NSLog", "printf", "fprintf", "CFShow", "NSURL URLWithString:", "NSURL fileURLWithPath:", "-[NSKeyedArchiver archivedDataWithRootObject:]", 
#     "+[NSJSONSerialization dataWithJSONObject:options:error:]", "+[NSPropertyListSerialization dataWithPropertyList:format:options:error:]", "UIAlertView", "UIActionSheet", "UIPasteboard", 
#     "JSContext evaluateScript:", "-[JSContext evaluateScript:]", "-[WKWebView evaluateJavaScript:completionHandler:]", "UITextField text", "UITextView text", 
#     "-[UIWebView stringByEvaluatingJavaScriptFromString:]", "NSURLSessionDataTask", "NSURLSessionUploadTask", "NSURLSessionDownloadTask", "NSURLConnection sendAsynchronousRequest:queue:completionHandler:"}

# Input source functions
inputFunctionsNamesSwift = ["UITextField","UITextView","UIDocumentPickerViewController","documentPicker","imagePickerController","pickerView","UIPasteboard.general.string","UIAlertController","locationManager","open","evaluateJavaScript"]
inputFunctionsNamesObjc = ["UITextField","UITextView","UIDatePicker","UIAlertView","NSFileManager","NSData","NSString","NSURLSession","NSURLConnection","NSStream","AFNetworking","NSUserDefaults","SecItemCopyMatching","SecItemAdd","SecItemUpdate","UIPasteboard","NSManagedObjectContext","FMDB","NSOpenPanel","NSProcessInfo","UIDevice","CLLocationManager","UIImagePickerController","AVCaptureDevice","fromRequest:getUsername:password:"]
# Sensitive functions
taintSinkFunctionsSwift = ["set","setPersistentDomain",    "FileManager.createFile","FileManager.copyItem","FileManager.moveItem","FileManager.removeItem","SecItemAdd", "SecItemUpdate","SecItemCopyMatching","SecItemDelete", "URLSession.dataTask","URLSession.uploadTask","URLSession.downloadTask","URLSessionWebSocketTask.send","FileHandle.write","NSXPCConnection.remoteObjectProxy","NSManagedObjectContext.save","NSManagedObjectContext.fetch","NSManagedObjectContext.delete","CCCrypt","CCCryptorCreate","CCCryptorUpdate","CCCryptorFinal","CryptoKit","SHA512.hash","AES.GCM.seal","AES.GCM.open","sqlite3_exec","sqlite3_prepare_v2","sqlite3_step","sqlite3_finalize","WKWebView.load","WKWebView.loadHTMLString","WKWebView.loadFileURL","UIPasteboard.general.setItems","UIPasteboard.general.setValue","UIPasteboard.general.setString","startUpdatingLocation","stopUpdatingLocation","AVAudioRecorder.record","AVCaptureSession.startRunning","AVCaptureSession.stopRunning"]
taintSinkFunctionsObjc = ["SecKeyEncrypt", "SecKeyDecrypt", "CCCrypt", "CCCryptorCreate", "CCCryptorUpdate", "CCCryptorFinal", "CryptoKit", "SHA512.hash", "AES.GCM.seal", "AES.GCM.open", "NSURLSessionDataTask", "NSURLSessionUploadTask", "NSURLSessionDownloadTask", "NSURLRequest", "sendSynchronousRequest", "connectionWithRequest", "sendAsynchronousRequest", "CFNetwork", "getStreamsToHostWithName", "openURL", "canOpenURL", "createFileAtPath", "copyItemAtPath", "moveItemAtPath", "removeItemAtPath", "initWithContentsOfFile", "setPassword", "setPasswordData", "setPasswordObject", "UIPasteboard", "loadRequest", "evaluateJavaScript", "evaluationScript", "assessmentJavaScript", "SecItemAdd", "SecItemUpdate", "SecItemCopyMatching", "SecItemDelete", "NSLog", "printf", "fprintf", "CFShow", "objc_msgSend", "objc_msgSendSuper", "dlopen", "dlsym", "system", "sqlite3_exec", "sqlite3_prepare_v2", "executeUpdateexecuteQuery"]

# #############################
# Function to get all taint sources (tainted variables)
def detectSources(function):
    # IDEA:
    # Look for functions that get data from user, and function parameters
    taint_sources = set()
    sourceFunctionName = {}
    for block in function.findall('Block'):
        for instruction in block:
            if instruction.tag == 'Parameter':
                name = instruction.attrib['name']
                taint_sources.add(name)
                sourceFunctionName[name] = 'Argument'
            if instruction.tag == 'Call':
                if 'return' in instruction.attrib: # voir si tous les fonctions ont avoir un variable de retour, sinon ca va donner un erreur
                    returnVar = instruction.attrib['return']
                    func = instruction.attrib['func']
                    if any(substring in func for substring in inputFunctionsNamesSwift) or any(substring in func for substring in inputFunctionsNamesObjc):
                        taint_sources.add(returnVar)
                        sourceFunctionName[returnVar] = func
    return taint_sources, sourceFunctionName
# #############################
# Function to track taint propagation
def taintPropagation(block, taint_sources, sourceFunctionName):
    tainted_vars = set(taint_sources)
    vulnerabilites = []
    for instruction in block:
        if instruction.tag == 'Assign':
            src = instruction.attrib['src']
            dest = instruction.attrib['dest']
            if src in tainted_vars:
                tainted_vars.add(dest)
                sourceFunctionName[dest] = sourceFunctionName[src]
        elif instruction.tag == 'Call':
            func = instruction.attrib['func']
            for arg in instruction.findall('Arg'):
                var = arg.attrib['var']
                if var in tainted_vars and (any(taintSinkFunction in func for taintSinkFunction in taintSinkFunctionsSwift) or any(taintSinkFunction in func for taintSinkFunction in taintSinkFunctionsObjc)):
                    vulnerabilites.append(f"Vulnérabilité potentielle : variable corrompue '{var}' propagation de la fonction '{sourceFunctionName[var]}' transmis à la fonction sensitive '{func}'")
    return vulnerabilites
# #############################
# Function to launch taint analysis
def taintAnalysisMain(xmlFileName, file):
    try:
        vulnerabilitesFichier = []
        tree = ET.parse(xmlFileName)
        root = tree.getroot()
        for function in root.findall('Function'):
            taint_sources, sourceFunctionName = detectSources(function)
            for block in function.findall('Block'):
                vulInFunction = taintPropagation(block, taint_sources, sourceFunctionName)
                if vulInFunction:
                    for vul in vulInFunction:
                        sourceCompletVul = vul + f" dans la fonction {function.attrib['name']} identifier par {function.attrib['id']}"
                        vulnerabilitesFichier.append(sourceCompletVul)
        return vulnerabilitesFichier
    except FileNotFoundError as e:
        print("FileNotFoundError for taint analysis")
        return None