#!/usr/bin/env python3
# filepath: malicious_code_detector.py

import os
import re
import base64
import argparse
import magic
import sys
import zlib
from pathlib import Path
from colorama import Fore, Style, init

# Initialize colorama for colored output
init()

def is_binary_file(file_path):
    """Check if file is binary"""
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        return not file_type.startswith('text/')
    except Exception as e:
        # Alternative check for issues with Magic library
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\0' in chunk
        except:
            return True  # Consider unreadable files as binary

def is_ignored_file(file_path, ignore_extensions):
    """Check if file should be ignored based on extensions"""
    return any(file_path.endswith(ext) for ext in ignore_extensions)

def is_base64_encoded(text):
    """Check if text contains base64 encoded content"""
    # Base64 regex pattern
    pattern = r'[A-Za-z0-9+/]{30,}={0,2}'
    try:
        matches = re.findall(pattern, text)
        
        for match in matches:
            try:
                # Try to decode and check if result is meaningful
                decoded = base64.b64decode(match)
                # Check if decoded content contains ASCII characters
                ascii_ratio = sum(32 <= byte <= 126 for byte in decoded) / len(decoded)
                if ascii_ratio > 0.7:  # At least 70% ASCII characters
                    return True, match
            except:
                pass
        
        return False, None
    except re.error as e:
        print(f"Warning: Error in base64 regex pattern: {str(e)}")
        return False, None

def is_hex_encoded(text):
    """Check if text contains hex-encoded content"""
    # Pattern for hex-encoded strings - Fixed to avoid bad character range
    pattern = r'(?:[0-9a-fA-F]{2}){20,}'
    try:
        matches = re.findall(pattern, text)
        
        for match in matches:
            if len(match) % 2 == 0:  # Valid hex should have even length
                try:
                    # Try to decode and check if result is meaningful
                    decoded = bytes.fromhex(match)
                    # Check if decoded content contains ASCII characters
                    ascii_ratio = sum(32 <= byte <= 126 for byte in decoded) / len(decoded)
                    if ascii_ratio > 0.7:  # At least 70% ASCII characters
                        return True, match
                except:
                    pass
        
        return False, None
    except re.error as e:
        print(f"Warning: Error in hex regex pattern: {str(e)}")
        return False, None

def is_gzip_data(text):
    """Check for gzip compressed data in strings"""
    # Common gzip magic bytes in hex form
    gzip_patterns = [
        r'1f8b08',  # Standard gzip header
        r'789c',    # Zlib header
        r'78da'     # Zlib header (another compression level)
    ]
    
    for pattern in gzip_patterns:
        if pattern in text.lower():
            try:
                # Find potential position and try to decompress
                pos = text.lower().find(pattern)
                if pos >= 0:
                    # Convert hex to bytes and try to decompress
                    hex_str = text[pos:pos+100].replace(' ', '')
                    if len(hex_str) % 2 != 0:
                        hex_str = hex_str[:-1]
                    
                    data = bytes.fromhex(hex_str)
                    decompressed = zlib.decompress(data)
                    
                    # Check if result contains readable text
                    ascii_ratio = sum(32 <= byte <= 126 for byte in decompressed) / len(decompressed)
                    if ascii_ratio > 0.6:
                        return True, hex_str[:30]
            except:
                pass
    
    return False, None

def contains_obfuscated_code(text):
    """Detect obfuscated JavaScript or other encrypted code types"""
    patterns = [
        # JavaScript eval obfuscation
        r'eval\s*\(\s*(?:function\s*\(\)\s*{|atob\s*\(|String\.fromCharCode|unescape\s*\()',
        # PHP long encoded strings
        r'\$[a-zA-Z0-9_]+\s*=\s*(\$[a-zA-Z0-9_]+\s*\.\s*){5,}',
        # Hex encoded content
        r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}',
        # Unicode escape sequences
        r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){10,}',
        # PHP base64 decode
        r'base64_decode\s*\(',
        # Document.write with obfuscation
        r'document\.write\s*\(\s*(?:atob|unescape|String\.fromCharCode)',
        # Suspicious function chains
        r'(\[["\'][a-zA-Z0-9_]+["\']\]){4,}',
        # Highly compressed looking JavaScript
        r'[a-zA-Z0-9_$]{1,3}(?:\[[a-zA-Z0-9_$]{1,3}\]|\.[a-zA-Z0-9_$]{1,3}){10,}',
        # PowerShell encoding
        r'-EncodedCommand',
        # JavaScript fromCharCode obfuscation
        r'(?:String\.)?fromCharCode\((?:\d+\s*,\s*){10,}',
        # Long array of numbers (possible ASCII values) - Fixed to avoid bad character range
        r'\[\s*(?:\d+\s*,\s*){20,}\d+\s*\]',
        # JavaScript unescape sequences
        r'unescape\(\s*[\'"][%0-9a-fA-F]+[\'"]\s*\)',
        # Python exec/eval with encoded strings
        r'(?:exec|eval)\s*\(\s*(?:base64|bytes\.fromhex|codecs\.decode)',
        # Reversed strings - FIXED: This pattern was causing the error
        r'(\[::-1\]|reversed\(|strrev\()',
        # Shell command obfuscation 
        r'sh -c [\'"]\$\([^)]+\)[\'"]',
        # Windows cmd obfuscation
        r'cmd\.exe\s+\/[a-z]\s+(?:set\s+\w+=|"(?:set\s+\w+=|%[^%]+%))',
        # Powershell cradle
        r'powershell\s+-(?:nop|noP|noprofile)\s+-(?:w|wi|win|window|windowstyle)\s+hidden',
    ]
    
    for pattern in patterns:
        try:
            if re.search(pattern, text):
                return True, pattern
        except re.error as e:
            print(f"Warning: Error in regex pattern '{pattern}': {str(e)}")
            continue
    
    return False, None

def detect_entropy_anomalies(text):
    """Detect high entropy segments which could indicate encrypted/encoded content"""
    if len(text) < 100:  # Skip small text segments
        return False, None
    
    # Create chunks
    chunks = [text[i:i+100] for i in range(0, len(text), 100)]
    
    for chunk in chunks:
        if len(chunk) < 20:
            continue
            
        # Calculate character frequency
        freq = {}
        for char in chunk:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        for char, count in freq.items():
            prob = count / len(chunk)
            entropy -= prob * (prob**0.5)  # Modified entropy calculation to detect anomalies
            
        # High entropy indicates possible encryption/encoding
        if entropy > 0.85 and len(freq) > 20:
            char_variance = len(freq) / len(chunk)
            if char_variance > 0.7:  # High variance suggests encryption
                return True, chunk[:30] + "..."
    
    return False, None

def scan_file(file_path):
    """Scan file for encrypted/suspicious code"""
    try:
        # Check file size, warn for large files
        file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB
        if file_size > 10:  # Files larger than 10 MB
            return [{'type': 'Info', 'message': f'File is very large ({file_size:.2f} MB), scanning might be slow'}]

        # Skip binary files
        if is_binary_file(file_path):
            return []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        findings = []
        
        # Try all detection methods with proper error handling
        try:
            # Base64 check
            is_base64, base64_sample = is_base64_encoded(content)
            if is_base64:
                findings.append({
                    'type': 'Base64 encoded content',
                    'sample': base64_sample[:50] + '...' if len(base64_sample) > 50 else base64_sample
                })
        except Exception as e:
            print(f"Error in base64 detection for {file_path}: {str(e)}")
            
        try:
            # Hex encoding check
            is_hex, hex_sample = is_hex_encoded(content)
            if is_hex:
                findings.append({
                    'type': 'Hex encoded content',
                    'sample': hex_sample[:50] + '...' if len(hex_sample) > 50 else hex_sample
                })
        except Exception as e:
            print(f"Error in hex detection for {file_path}: {str(e)}")
            
        try:
            # Check for compressed data
            is_compressed, compressed_sample = is_gzip_data(content)
            if is_compressed:
                findings.append({
                    'type': 'Compressed data found',
                    'sample': compressed_sample
                })
        except Exception as e:
            print(f"Error in compression detection for {file_path}: {str(e)}")
            
        try:
            # Entropy analysis
            high_entropy, entropy_sample = detect_entropy_anomalies(content)
            if high_entropy:
                findings.append({
                    'type': 'High entropy data (possible encryption)',
                    'sample': entropy_sample
                })
        except Exception as e:
            print(f"Error in entropy analysis for {file_path}: {str(e)}")
        
        try:
            # Obfuscated code check
            is_obfuscated, pattern = contains_obfuscated_code(content)
            if is_obfuscated:
                findings.append({
                    'type': 'Obfuscated/encrypted code',
                    'pattern': pattern
                })
        except Exception as e:
            print(f"Error in obfuscation detection for {file_path}: {str(e)}")
            
        return findings
        
    except Exception as e:
        return [{'type': 'Error', 'message': f'Error scanning file: {str(e)}'}]

def safe_regex_search(pattern, text):
    """Safely perform a regex search with error handling"""
    try:
        return re.search(pattern, text)
    except re.error as e:
        print(f"Regex error with pattern '{pattern}': {str(e)}")
        return None

def scan_directory(directory, ignore_extensions=['.jpg', '.png', '.gif', '.mp4', '.pdf', '.zip'], max_file_size=10):
    """Scan specified directory and subdirectories for files"""
    suspicious_files = {}
    error_files = {}
    skipped_files = {}
    
    print(f"{Fore.BLUE}Scanning: {directory}{Style.RESET_ALL}")
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            
            if is_ignored_file(file_path, ignore_extensions):
                continue
            
            try:
                # Check file size
                file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB
                if file_size > max_file_size:
                    skipped_files[file_path] = f"File too large: {file_size:.2f} MB"
                    continue
                    
                findings = scan_file(file_path)
                
                # Store results with errors separately
                has_error = any(f.get('type') == 'Error' for f in findings)
                if has_error:
                    error_files[file_path] = findings
                elif findings:
                    suspicious_files[file_path] = findings
            
            except Exception as e:
                error_files[file_path] = [{'type': 'Error', 'message': f'Processing error: {str(e)}'}]
                
    return suspicious_files, error_files, skipped_files

def display_menu():
    """Display the main menu"""
    print(f"\n{Fore.CYAN}======== Malicious Code Detector ========{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Scan File")
    print(f"{Fore.YELLOW}2.{Style.RESET_ALL} Scan Directory")
    print(f"{Fore.YELLOW}3.{Style.RESET_ALL} Help")
    print(f"{Fore.YELLOW}4.{Style.RESET_ALL} Exit")
    print(f"{Fore.CYAN}========================================{Style.RESET_ALL}")

def interactive_mode():
    """Interactive mode for user interface"""
    ignore_extensions_default = '.jpg,.jpeg,.png,.gif,.mp4,.mp3,.pdf,.zip,.exe,.dll'
    
    while True:
        display_menu()
        choice = input(f"{Fore.GREEN}Your choice (1-4): {Style.RESET_ALL}")
        
        if choice == '1':
            file_path = input(f"{Fore.GREEN}Enter file path to scan: {Style.RESET_ALL}")
            if not os.path.exists(file_path):
                print(f"{Fore.RED}Error: File not found!{Style.RESET_ALL}")
                continue
                
            if not os.path.isfile(file_path):
                print(f"{Fore.RED}Error: Not a file!{Style.RESET_ALL}")
                continue
                
            print(f"{Fore.BLUE}Scanning file: {file_path}{Style.RESET_ALL}")
            findings = scan_file(file_path)
            if findings:
                has_error = any(f.get('type') == 'Error' for f in findings)
                if has_error:
                    print(f"\n{Fore.RED}⚠️  FILE SCAN ERROR: {file_path}{Style.RESET_ALL}")
                else:
                    print(f"\n{Fore.RED}⚠️  SUSPICIOUS CODE DETECTED: {file_path}{Style.RESET_ALL}")
                    
                for finding in findings:
                    print(f"{Fore.YELLOW}Type: {finding['type']}{Style.RESET_ALL}")
                    if 'sample' in finding:
                        print(f"Sample: {finding['sample']}")
                    if 'pattern' in finding:
                        print(f"Matched pattern: {finding['pattern']}")
                    if 'message' in finding:
                        print(f"Message: {finding['message']}")
            else:
                print(f"{Fore.GREEN}✓ No suspicious code detected: {file_path}{Style.RESET_ALL}")
                
        elif choice == '2':
            dir_path = input(f"{Fore.GREEN}Enter directory path to scan: {Style.RESET_ALL}")
            if not os.path.exists(dir_path):
                print(f"{Fore.RED}Error: Directory not found!{Style.RESET_ALL}")
                continue
                
            if not os.path.isdir(dir_path):
                print(f"{Fore.RED}Error: Not a directory!{Style.RESET_ALL}")
                continue
            
            custom_ignore = input(f"{Fore.GREEN}Enter extensions to ignore (leave empty for default): {Style.RESET_ALL}")
            ignore_extensions = custom_ignore.split(',') if custom_ignore else ignore_extensions_default.split(',')
            
            max_size = input(f"{Fore.GREEN}Maximum file size (MB, default=10): {Style.RESET_ALL}")
            try:
                max_file_size = float(max_size) if max_size else 10
            except:
                max_file_size = 10
                
            suspicious_files, error_files, skipped_files = scan_directory(dir_path, ignore_extensions, max_file_size)
            
            # Show files with suspicious code
            if suspicious_files:
                print(f"\n{Fore.RED}⚠️  SUSPICIOUS CODE DETECTED IN {len(suspicious_files)} FILES{Style.RESET_ALL}")
                for file_path, findings in suspicious_files.items():
                    print(f"\n{Fore.RED}⚠️  {file_path}{Style.RESET_ALL}")
                    for finding in findings:
                        print(f"{Fore.YELLOW}Type: {finding['type']}{Style.RESET_ALL}")
                        if 'sample' in finding:
                            print(f"Sample: {finding['sample']}")
                        if 'pattern' in finding:
                            print(f"Matched pattern: {finding['pattern']}")
                        if 'message' in finding:
                            print(f"Message: {finding['message']}")
            else:
                print(f"\n{Fore.GREEN}✓ No suspicious code detected in the directory{Style.RESET_ALL}")
                
            # Show files with errors
            if error_files:
                print(f"\n{Fore.YELLOW}⚠️  ERRORS OCCURRED IN {len(error_files)} FILES{Style.RESET_ALL}")
                for file_path, findings in error_files.items():
                    print(f"\n{Fore.YELLOW}⚠️  {file_path}{Style.RESET_ALL}")
                    for finding in findings:
                        if 'message' in finding:
                            print(f"Message: {finding['message']}")
                            
            # Show skipped files
            if skipped_files:
                print(f"\n{Fore.BLUE}ℹ️  {len(skipped_files)} FILES SKIPPED{Style.RESET_ALL}")
                print(f"Note: Use '-i' parameter to add more file extensions or increase maximum file size to scan these files")
                
        elif choice == '3':
            print(f"\n{Fore.CYAN}===== HELP =====")
            print("This tool helps you detect malicious or encoded code snippets in files")
            print("1. Scan File: Analyze a single file")
            print("2. Scan Directory: Recursively scan all files in a directory")
            print(f"Default ignored extensions: {ignore_extensions_default}")
            print(f"===================={Style.RESET_ALL}")
            
        elif choice == '4':
            print(f"{Fore.CYAN}Exiting program...{Style.RESET_ALL}")
            break
            
        else:
            print(f"{Fore.RED}Invalid selection, please try again.{Style.RESET_ALL}")
        
        input(f"\n{Fore.CYAN}Press any key to continue...{Style.RESET_ALL}")

def main():
    # Check for drag and drop operation using sys.argv
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
        path = sys.argv[1]
        if os.path.exists(path):
            # Item is a directory or file
            print(f"{Fore.CYAN}Drag-and-drop scan started: {path}{Style.RESET_ALL}")
            
            # Start scan with default settings
            ignore_extensions = '.jpg,.jpeg,.png,.gif,.mp4,.mp3,.pdf,.zip,.exe,.dll'.split(',')
            max_file_size = 10
            
            if os.path.isfile(path):
                findings = scan_file(path)
                if findings:
                    has_error = any(f.get('type') == 'Error' for f in findings)
                    if has_error:
                        print(f"\n{Fore.YELLOW}⚠️  FILE SCAN ERROR: {path}{Style.RESET_ALL}")
                    else:
                        print(f"\n{Fore.RED}⚠️  SUSPICIOUS CODE DETECTED: {path}{Style.RESET_ALL}")
                    
                    for finding in findings:
                        print(f"{Fore.YELLOW}Type: {finding['type']}{Style.RESET_ALL}")
                        if 'sample' in finding:
                            print(f"Sample: {finding['sample']}")
                        if 'pattern' in finding:
                            print(f"Matched pattern: {finding['pattern']}")
                        if 'message' in finding:
                            print(f"Message: {finding['message']}")
                else:
                    print(f"{Fore.GREEN}✓ No suspicious code detected: {path}{Style.RESET_ALL}")
            else:
                suspicious_files, error_files, skipped_files = scan_directory(path, ignore_extensions, max_file_size)
                
                if suspicious_files:
                    print(f"\n{Fore.RED}⚠️  SUSPICIOUS CODE DETECTED IN {len(suspicious_files)} FILES{Style.RESET_ALL}")
                    for file_path, findings in suspicious_files.items():
                        print(f"\n{Fore.RED}⚠️  {file_path}{Style.RESET_ALL}")
                        for finding in findings:
                            print(f"{Fore.YELLOW}Type: {finding['type']}{Style.RESET_ALL}")
                            if 'sample' in finding:
                                print(f"Sample: {finding['sample']}")
                            if 'pattern' in finding:
                                print(f"Matched pattern: {finding['pattern']}")
                            if 'message' in finding:
                                print(f"Message: {finding['message']}")
                else:
                    print(f"\n{Fore.GREEN}✓ No suspicious code detected in the directory{Style.RESET_ALL}")
                    
                if error_files:
                    print(f"\n{Fore.YELLOW}⚠️  ERRORS OCCURRED IN {len(error_files)} FILES{Style.RESET_ALL}")
                    for file_path, findings in error_files.items():
                        print(f"\n{Fore.YELLOW}⚠️  {file_path}{Style.RESET_ALL}")
                        for finding in findings:
                            if 'message' in finding:
                                print(f"Message: {finding['message']}")
                                
                if skipped_files:
                    print(f"\n{Fore.BLUE}ℹ️  {len(skipped_files)} FILES SKIPPED{Style.RESET_ALL}")
            
            print(f"\n{Fore.CYAN}Scan completed. Press any key to exit...{Style.RESET_ALL}")
            input()
            return
            
    # Process command line arguments
    parser = argparse.ArgumentParser(description='Malicious code detector for files and directories')
    parser.add_argument('path', nargs='?', help='File or directory path to scan (leave empty for interactive mode)')
    parser.add_argument('--ignore', '-i', help='File extensions to ignore (comma separated)',
                        default='.jpg,.jpeg,.png,.gif,.mp4,.mp3,.pdf,.zip,.exe,.dll')
    parser.add_argument('--max-size', '-m', type=float, help='Maximum file size (MB)', default=10)
    args = parser.parse_args()
    
    # If no path provided, switch to interactive mode
    if not args.path:
        interactive_mode()
        return
    
    path = Path(args.path)
    ignore_extensions = args.ignore.split(',')
    
    if not path.exists():
        print(f"{Fore.RED}Error: Path not found: {path}{Style.RESET_ALL}")
        return
    
    if path.is_file():
        findings = scan_file(str(path))
        if findings:
            has_error = any(f.get('type') == 'Error' for f in findings)
            if has_error:
                print(f"\n{Fore.YELLOW}⚠️  FILE SCAN ERROR: {path}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.RED}⚠️  SUSPICIOUS CODE DETECTED: {path}{Style.RESET_ALL}")
                
            for finding in findings:
                print(f"{Fore.YELLOW}Type: {finding['type']}{Style.RESET_ALL}")
                if 'sample' in finding:
                    print(f"Sample: {finding['sample']}")
                if 'pattern' in finding:
                    print(f"Matched pattern: {finding['pattern']}")
                if 'message' in finding:
                    print(f"Message: {finding['message']}")
        else:
            print(f"{Fore.GREEN}✓ No suspicious code detected: {path}{Style.RESET_ALL}")
    else:
        suspicious_files, error_files, skipped_files = scan_directory(str(path), ignore_extensions, args.max_size)
        
        # Show files with suspicious code
        if suspicious_files:
            print(f"\n{Fore.RED}⚠️  SUSPICIOUS CODE DETECTED IN {len(suspicious_files)} FILES{Style.RESET_ALL}")
            for file_path, findings in suspicious_files.items():
                print(f"\n{Fore.RED}⚠️  {file_path}{Style.RESET_ALL}")
                for finding in findings:
                    print(f"{Fore.YELLOW}Type: {finding['type']}{Style.RESET_ALL}")
                    if 'sample' in finding:
                        print(f"Sample: {finding['sample']}")
                    if 'pattern' in finding:
                        print(f"Matched pattern: {finding['pattern']}")
                    if 'message' in finding:
                        print(f"Message: {finding['message']}")
        else:
            print(f"\n{Fore.GREEN}✓ No suspicious code detected in the directory{Style.RESET_ALL}")
            
        # Show files with errors
        if error_files:
            print(f"\n{Fore.YELLOW}⚠️  ERRORS OCCURRED IN {len(error_files)} FILES{Style.RESET_ALL}")
            for file_path, findings in error_files.items():
                print(f"\n{Fore.YELLOW}⚠️  {file_path}{Style.RESET_ALL}")
                for finding in findings:
                    if 'message' in finding:
                        print(f"Message: {finding['message']}")
                        
        # Show skipped files
        if skipped_files:
            print(f"\n{Fore.BLUE}ℹ️  {len(skipped_files)} FILES SKIPPED{Style.RESET_ALL}")
            print(f"Note: Use '-i' parameter to add more file extensions or '--max-size' to increase maximum file size")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.CYAN}Program terminated by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()  # Print full stack trace for better debugging
        
    # Prevent console from closing immediately when drag-and-dropped
    if len(sys.argv) > 1 and not sys.argv[0].endswith('.py'):
        input(f"\n{Fore.CYAN}Press any key to exit...{Style.RESET_ALL}")
