import os
import sys
import zipfile
import plistlib

def extract_ipa(ipa_path):
    # Create a temporary directory for extraction
    extract_dir = os.path.splitext(ipa_path)[0]
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
    return extract_dir

def find_info_plist(extract_dir):
    # Navigate to the Info.plist file inside the .app directory
    for root, dirs, files in os.walk(extract_dir):
        for file in files:
            if file == 'Info.plist':
                return os.path.join(root, file)
    return None

def read_plist(plist_path):
    with open(plist_path, 'rb') as plist_file:
        plist_content = plistlib.load(plist_file)
    return plist_content

def find_macho(extract_dir, executable_name):
    # Look for the Mach-O executable inside the .app directory
    for root, dirs, files in os.walk(extract_dir):
        if executable_name in files:
            return os.path.join(root, executable_name)
    return None

def main():
    # Get the IPA file path from the user
    ipa_path = input("Enter the path to the .ipa file: ")

    if not os.path.isfile(ipa_path) or not ipa_path.endswith('.ipa'):
        print("Please provide a valid .ipa file path.")
        sys.exit(1)

    # Step 1: Extract the IPA
    extract_dir = extract_ipa(ipa_path)
    
    # Step 2: Find the Info.plist file
    plist_path = find_info_plist(extract_dir)
    
    if not plist_path:
        print("Info.plist file not found.")
        sys.exit(1)
    
    # Step 3: Read the Info.plist and get the executable name
    plist_content = read_plist(plist_path)
    executable_name = plist_content.get('CFBundleExecutable', None)
    
    if not executable_name:
        print("Executable name not found in Info.plist.")
        sys.exit(1)

    # Step 4: Find the Mach-O executable
    macho_path = find_macho(extract_dir, executable_name)
    
    if macho_path:
        print(f"Mach-O executable found at: {macho_path}")
    else:
        print("Mach-O executable not found.")
        sys.exit(1)

if __name__ == "__main__":
    main()
