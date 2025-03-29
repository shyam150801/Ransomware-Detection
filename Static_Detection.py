import hashlib
import pefile
import re
import math
import requests
import yara
import json

# VirusTotal API key (replace with your actual key)
API_KEY = '3fc71fe8a0245645ba331af807d05fd2923789aeedbfe2a802db23d2ad95e81a'

# Function to compute file hash
def compute_hash(file_path, algorithm='sha256'):
    hash_func = hashlib.new(algorithm)
    with open(file_path, 'rb') as file:
        while chunk := file.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()

# Function to check file format (PE)
def check_file_format(file_path):
    with open(file_path, 'rb') as file:
        magic_number = file.read(2)
    return magic_number == b'MZ'

# Function to check hash against VirusTotal database
def check_hash_virustotal(file_hash, save_path="virustotal_report.json"):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {
        'apikey': API_KEY,
        'resource': file_hash
    }
    response = requests.get(url, params=params)
    
    if response.status_code == 200:
        json_response = response.json()
        
        # Save JSON report locally
        with open(save_path, "w") as f:
            json.dump(json_response, f, indent=4)

        if json_response.get('positives', 0) > 0:
            print(f"VirusTotal Detection: {json_response['positives']}/{json_response['total']} engines detected malware.")
            if 'ransomware' in str(json_response).lower():
                return True  # Likely ransomware
        else:
            print("VirusTotal: No malware detected.")
    
    elif response.status_code == 403:
        print("Error querying VirusTotal: Forbidden (403). Possible reasons: Invalid API key or rate limit exceeded.")
    else:
        print(f"Error querying VirusTotal: {response.status_code}")
    
    return False

# PE Header Analysis
def pe_header_analysis(file_path):
    if check_file_format(file_path):
        print("Analyzing PE headers...")
        try:
            pe = pefile.PE(file_path)
            return []  # Example, replace with actual function results
        except Exception as e:
            print(f"Error inspecting PE headers: {e}")
    else:
        print("File is not a valid PE file. Skipping PE header analysis.")
    return []

# Inspect PE Headers
def inspect_pe_headers(file_path):
    suspicious_functions = []
    if check_file_format(file_path):
        try:
            pe = pefile.PE(file_path)
            suspicious_imports = ["VirtualAlloc", "CreateFileA", "WriteFile", "CryptEncrypt", "CryptDecrypt", "RegCreateKeyA"]
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name is not None and imp.name.decode() in suspicious_imports:
                        suspicious_functions.append(imp.name.decode())
        except Exception as e:
            print(f"Error inspecting PE headers: {e}")
    return suspicious_functions

# String Extraction
def extract_strings(file_path, min_length=4):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        
        ascii_strings = re.findall(rb'[\x20-\x7E]{%d,}' % min_length, data)
        unicode_strings = re.findall(rb'(?:[\x20-\x7E][\x00]){%d,}' % min_length, data)
        
        all_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings] + \
                      [s.decode('utf-16', errors='ignore') for s in unicode_strings]
        
        suspicious_indicators = ["decrypt", "encrypt", "bitcoin", "ransom", "key", "payment"]
        detected_suspicious_strings = [s for s in all_strings if any(indicator in s.lower() for indicator in suspicious_indicators)]
        
        return detected_suspicious_strings
    except Exception as e:
        print(f"Error extracting strings: {e}")
        return []

# Entropy Calculation
def calculate_entropy(data):
    if not data:
        return 0

    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    entropy = 0
    for count in byte_counts:
        if count:
            p_x = count / len(data)
            entropy -= p_x * math.log2(p_x)

    return entropy

def file_entropy(file_path):
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        entropy = calculate_entropy(data)
        return entropy
    except Exception as e:
        print(f"Error calculating entropy: {e}")
        return 0

# YARA Rule Matching (Ransomware Family Detection)
def yara_scan(file_path):
    try:
        # Define YARA rules
        yara_rules = """
        rule Ransomware_Family_Detection {
            meta:
                description = "Detects multiple ransomware families: WannaCry, Locky, CryptoLocker, REvil, Ryuk"
                author = "YARA rule example"
                date = "2024-10-20"
                version = "1.0"
                
            strings:
                // WannaCry
                $wannacry_1 = "WannaDecryptor" wide
                $wannacry_2 = "WannaCry" wide
                $wannacry_3 = "WNcry@2ol7" wide

                // Locky
                $locky_ext = ".locky" nocase
                $locky_str = "the installation of software must be authorized by the administrator"

                // CryptoLocker
                $cryptolocker_note = "Your personal files are encrypted!"
                $cryptolocker_name = "CryptoLocker" nocase
                $cryptolocker_rsa = "BEGIN PUBLIC KEY" ascii

                // REvil/Sodinokibi
                $revil_ext = ".sodinokibi" nocase
                $revil_msg = "REvil"
                $revil_key = "-----BEGIN REvil PRIVATE KEY-----" ascii

                // Ryuk
                $ryuk_note = "RyukReadMe" wide
                $ryuk_str1 = "Ryuk" wide
                $ryuk_key = "-----BEGIN PRIVATE KEY-----"

                // Common PE header
                $mz_header = { 4D 5A } // MZ header for PE files

            condition:
                (uint16(0) == 0x5A4D) and // PE file
                filesize < 10MB and (
                    // WannaCry conditions
                    (all of ($wannacry_*) or
                    // Locky conditions
                    ($locky_ext or $locky_str) or
                    // CryptoLocker conditions
                    ($cryptolocker_note or $cryptolocker_name or $cryptolocker_rsa) or
                    // REvil conditions
                    ($revil_ext or $revil_msg or $revil_key) or
                    // Ryuk conditions
                    ($ryuk_note or $ryuk_str1 or $ryuk_key)) or
                    // Common PE header
                    ($mz_header)
                )
        }

        """
        
        # Compile YARA rules from string
        rules = yara.compile(source=yara_rules)
        
        # Scan the file for matches
        matches = rules.match(file_path)
        
        if matches:
            print(f"YARA detected ransomware families with rules: {matches}")
            return True  # YARA found ransomware indicators
        else:
            print("No YARA rule matches found.")
    except yara.Error as e:
        print(f"Error in YARA scanning: {e}")
    return False

# Final ransomware detection script with YARA integration
def ransomware_static_analysis(file_path):
    print("Starting static analysis...")

    # Variables to store scores for each module
    score = 0
    entropy_threshold = 3
    suspicious_threshold = 2  # Total score needed to classify as ransomware

    # Step 1: File Hashing and VirusTotal Check
    print("\n[1] File Hashing and VirusTotal Check")
    hash_value = compute_hash(file_path, 'sha256')
    print(f"SHA-256 Hash: {hash_value}")
    
    # VirusTotal check
    is_ransomware_vt = check_hash_virustotal(hash_value)
    if is_ransomware_vt:
        print("The file is likely ransomware according to VirusTotal.")
        score += 100

    # Step 2: PE Header Analysis
    print("\n[2] PE Header Analysis")
    suspicious_functions = []
    if check_file_format(file_path):
        pe_header_analysis(file_path)
        suspicious_functions = inspect_pe_headers(file_path)
        if suspicious_functions:
            print("Suspicious API calls found in imports:")
            for func in suspicious_functions:
                print(f" - {func}")
            score += 1
        else:
            print("No suspicious API calls detected.")
    else:
        print("PE analysis skipped: File is not a PE.")

    # Step 3: String Extraction
    print("\n[3] String Extraction")
    suspicious_strings = extract_strings(file_path)
    if suspicious_strings:
        print("Suspicious strings found:")
        for string in suspicious_strings[:10]:
            print(f" - {string}")
        score += 1
    else:
        print("No suspicious strings found.")
    
    # Step 4: File Entropy Calculation
    print("\n[4] Entropy Calculation")
    entropy = file_entropy(file_path)
    print(f"File entropy: {entropy}")
    if entropy > entropy_threshold:
        print(f"High entropy detected! (> {entropy_threshold})")
        score += 1
    else:
        print(f"Entropy is below the threshold of {entropy_threshold}.")
    
    # Step 5: YARA Rule Scanning (Ransomware Family Detection)
    print("\n[5] YARA Rule Scanning (Ransomware Family Detection)")
    yara_result = yara_scan(file_path)
    if yara_result:
        print("YARA detected ransomware behavior.")
        score += 100
    else:
        print("No ransomware patterns detected by YARA.")

    # Final Score Evaluation
    print("\nFinal Score Evaluation:")
    if score >= suspicious_threshold:
        print(f"The file is likely ransomware based on static analysis. [Score: {score}]")
    else:
        print(f"The file is unlikely to be ransomware. [Score: {score}]")

# Example Usage:
file_to_analyze = "test.bat"
ransomware_static_analysis(file_to_analyze)

