import os
import sys
import zipfile
import plistlib
import shutil

def extractIPA(ipaFilePath):
    # Create a temporary directory for extraction
    extract_dir = os.path.splitext(ipaFilePath)[0] +"Unzipped"
    with zipfile.ZipFile(ipaFilePath, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
    return extract_dir

def findInfoPlistFile(extract_dir):
    # Navigate to the Info.plist file inside the .app directory
    for root, dirs, files in os.walk(extract_dir):
        for file in files:
            if file == 'Info.plist':
                return os.path.join(root, file)
    return None

def readInfoPlistFile(plist_path):
    with open(plist_path, 'rb') as plist_file:
        plist_content = plistlib.load(plist_file)
    return plist_content

def findMACHO(extract_dir, executable_name):
    # Look for the Mach-O executable inside the .app directory
    for root, dirs, files in os.walk(extract_dir):
        if executable_name in files:
            return os.path.join(root, executable_name)
    return None

def extractBinaryFile(ipaFilePath):
    if not os.path.isfile(ipaFilePath) or not ipaFilePath.endswith('.ipa'):
        print("Please provide a valid .ipa file path.")
        sys.exit(1)
    # Step 1: Extract the IPA
    extract_dir = extractIPA(ipaFilePath)
    # Step 2: Find the Info.plist file
    plist_path = findInfoPlistFile(extract_dir)
    if not plist_path:
        print("Info.plist file not found.")
        sys.exit(1)
    # Step 3: Read the Info.plist and get the executable name
    plist_content = readInfoPlistFile(plist_path)
    executable_name = plist_content.get('CFBundleExecutable', None)
    if not executable_name:
        print("Executable name not found in Info.plist.")
        sys.exit(1)
    # Step 4: Find the Mach-O executable and copy
    macho_path = findMACHO(extract_dir, executable_name)
    if macho_path:
        try:
            # Copy the Mach-O file to the .ipa file's directory
            dest_path = os.path.join(os.path.dirname(ipaFilePath), os.path.basename(macho_path))
            shutil.copy(macho_path, dest_path)
            shutil.rmtree(extract_dir)
            os.remove(ipaFilePath)
        except PermissionError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        print("Mach-O executable not found.")
        sys.exit(1)