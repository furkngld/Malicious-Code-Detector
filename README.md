# Malicious Code Detector

A powerful Python tool for detecting potentially malicious or obfuscated code in files and directories. This scanner helps security researchers, developers, and system administrators identify suspicious code patterns, encoded/encrypted content, and possible malware indicators.

## 🔍 Features

- Detects various types of suspicious code:
  - Base64 encoded content
  - Hex encoded strings
  - Compressed/gzipped data
  - High entropy data (possible encryption)
  - Obfuscated code patterns
  
- Comprehensive scanning options:
  - Single file analysis
  - Full directory recursive scanning
  - Drag-and-drop interface for Windows users
  - Interactive console menu
  
- Smart file handling:
  - Automatically skips binary files
  - Configurable file type exclusions
  - Maximum file size limits
  
- User-friendly interface:
  - Color-coded output for easy reading
  - Detailed findings reports
  - Error handling and reporting

## 📋 Requirements

- Python 3.6+
- Required packages:
  - colorama
  - python-magic (for UNIX/Linux) or python-magic-bin (for Windows)

## 🚀 Installation

1. Clone this repository:
```bash
git clone https://github.com/furkngld/malicious-code-detector.git
cd malicious-code-detector
```

2. Install required packages:
```bash
# For Windows
pip install colorama python-magic-bin

# For Linux/MacOS
pip install colorama python-magic
```

## 💻 Usage

### Interactive Mode

Run the script without arguments to use the interactive menu:

```bash
python detect.py
```

This will display a menu with the following options:
1. Scan File
2. Scan Directory
3. Help
4. Exit

### Command Line Interface

Scan a specific file:
```bash
python detect.py path/to/suspicious_file.js
```

Scan an entire directory:
```bash
python detect.py path/to/directory
```

### Additional Options

Customize ignored extensions:
```bash
python detect.py path/to/scan --ignore=".jpg,.png,.mp3"
```

Set maximum file size (in MB):
```bash
python detect.py path/to/scan --max-size=20
```

### Windows Drag-and-Drop

In Windows environments, you can simply drag and drop files or folders onto the script executable to scan them with default settings.

## 📷 Screenshots

*Interactive menu interface*

![Interactive Menu](https://github.com/user-attachments/assets/ad3ea9f2-1e8b-4e7b-8514-5e124ecf74e1)

*Example of scan results showing detected malicious patterns*

![Scan Results](https://github.com/user-attachments/assets/a2809449-8daa-4bdf-9016-0a38aef02f4e)

## ⚙️ How it Works

The tool employs multiple detection techniques to identify suspicious code:

1. **Pattern Matching**: Uses regex patterns to identify common obfuscation techniques
2. **Entropy Analysis**: Detects high-entropy segments that may indicate encryption
3. **Encoding Detection**: Identifies base64, hex, and other common encoding methods
4. **Compression Detection**: Finds compressed data embedded in text files
5. **Heuristic Analysis**: Examines code for suspicious patterns and techniques commonly used by malware

## 🛡️ Use Cases

- Scanning downloaded code before execution
- Auditing web applications for security issues
- Checking user-submitted content for malicious code
- Validating open-source packages
- Forensic analysis of potentially compromised systems

## 📝 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for defensive security purposes only. It should be used responsibly and ethically to improve security posture. The authors are not responsible for any misuse or damage caused by this program.
