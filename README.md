# YARA-ALL-THE-WAY
Project of Team BingChilling for KrackHack 2.0 
## Overview

**YARA-ALL-THE-WAY** is one of the best and easiest-to-use static analysis tools designed to detect malicious files across various formats like `.exe`, `.pdf`, `.docx`, and more. By leveraging **YARA rules**, **file headers**, and **static indicators**, we perform **deep inspection** without executing the file. Our solution integrates **Python's PE file analysis** and **VirusTotal API** to ensure robust detection.

Static analysis is a critical approach in malware detection as it allows us to identify potential threats based on predefined rules and patterns without executing the file. This method is effective for identifying known malware, embedded malicious scripts, and obfuscation techniques used by attackers.

---
 
      \ \/ /   |  / __ \/   |     \ \/ /   |  / __ \/   |     \ \/ /   |  / __ \/   |
       \  / /| | / /_/ / /| |      \  / /| | / /_/ / /| |      \  / /| | / /_/ / /| |
       / / ___ |/ _, _/ ___ |      / / ___ |/ _, _/ ___ |      / / ___ |/ _, _/ ___ |
      /_/_/  |_/_/ |_/_/  |_|     /_/_/  |_/_/ |_/_/  |_|     /_/_/  |_/_/ |_/_/  |_|
      \ \/ /   |  / __ \/   |     \ \/ /   |  / __ \/   |     \ \/ /   |  / __ \/   |
       \  / /| | / /_/ / /| |      \  / /| | / /_/ / /| |      \  / /| | / /_/ / /| |
       / / ___ |/ _, _/ ___ |      / / ___ |/ _, _/ ___ |      / / ___ |/ _, _/ ___ |
      /_/_/  |_/_/ |_/_/  |_|     /_/_/  |_/_/ |_/_/  |_|     /_/_/  |_/_/ |_/_/  |_|
      \ \/ /   |  / __ \/   |     \ \/ /   |  / __ \/   |     \ \/ /   |  / __ \/   |
       \  / /| | / /_/ / /| |      \  / /| | / /_/ / /| |      \  / /| | / /_/ / /| |
       / / ___ |/ _, _/ ___ |      / / ___ |/ _, _/ ___ |      / / ___ |/ _, _/ ___ |
      /_/_/  |_/_/ |_/_/  |_|     /_/_/  |_/_/ |_/_/  |_|     /_/_/  |_/_/ |_/_/  |_|
     


## Tech Stack
- **Frontend:** React.js
- **Backend:** Flask (Python)
- **Static Analysis:** YARA, PEfile, PDFID
- **Threat Intelligence:** YARA rules

### YARA Rule Sources
- [YARA Rules Repository](https://github.com/Yara-Rules/rules)
- [YARA Forge](https://yaraify.abuse.ch/)
- [Malpedia YARA Rules](https://malpedia.caad.fkie.fraunhofer.de/)

---

## How It Works

### **Step-by-Step Process**
1. **File Upload & Type Detection**:
   - The user uploads a file via the frontend.
   - We identify the file type based on its **magic number** and **headers**.

2. **Static Analysis Checks**:
   - If it's an **EXE file**:
     - We extract **PE sections, imports, and entropy analysis**.
     - We check for **UPX packing**.
     - We run **YARA rules** to detect known malware signatures.
   - If it's a **PDF file**:
     - We check for **JavaScript embedding**.
     - We scan for **malicious links and phishing indicators**.
     - We apply **YARA rules** for PDF-specific threats.
   - If it's a **DOCX file**:
     - We inspect for **macro-based malware**.
     - We extract **embedded OLE objects**.
     - We scan with **YARA rules** targeting document-based attacks.

3. **File Hashing & VirusTotal Check**:
   - We compute the **SHA256 hash** of the file.
   - The hash is sent to **VirusTotal API** for additional threat intelligence.
   - If the file has been flagged by VirusTotal, we mark it accordingly.

4. **Final Verdict & Response**:
   - We combine results from **YARA matches**, **static indicators**, and **VirusTotal feedback**.
   - The user gets a response: `SAFE` or `MALICIOUS`.
   - Additional metadata like **file entropy, embedded objects, and suspicious APIs** is included.

---

## Limitations of Static Analysis

🚨 **Static analysis alone is not foolproof!**
- It **cannot detect polymorphic or heavily obfuscated malware**.
- **Packers and crypters** can bypass static detection.
- **Zero-day threats** may evade known YARA rules.
- **Dynamic behavior of malware is not analyzed**.
- **PDF & DOCX Analysis Limitations:**
  - If a **PDF file** contains links, static analysis can only determine that links exist but **cannot verify if they are actually dangerous**.
  - If a **DOCX file** contains macros or embedded objects, static analysis can detect their presence but **cannot execute them to check for real-time malicious behavior**.

For a more comprehensive threat analysis, consider using **dynamic analysis in a sandbox environment** alongside static checks. 🚀

**Python Code Analysis** 
•	First we import all the modules re, magic, docx, PyPDF2, shutil, YARA, os, hashlib, counter ,pefile, math.
•	Calculating the entropy and checking if the entropy is high(>7.5).
  o	If entropy is high, there may be possible obfuscation and packing. To check that we create a function.
  o	We also check if there are hidden suspicious APIs.
•	We calculate the hash of our file(SHA 256) and out normal hash(using imphash).
•	We already created a list of suspicious APIs. So now we use PEfile to detect the suspicious APIs.
•	The code checks if a PE (Portable Executable) file contains TLS callbacks, which are used for pre-entry point execution. If TLS callbacks are present, it returns True, otherwise False.
•	The code checks for overlay in a PE file—extra data appended after the last section. It compares the file size with the end of the last section and returns True if an overlay is detected, otherwise False.
•	Now we access text from PDFs and DOCX files to check. If there are any URLs in the file, it lets you know.
•	Now we find the type of the file and assign specific set of YARA rules according to the file type.
If there is a text file, the it converts it to exe and pdf file, it checks for both.
•	Now files are checked with corresponding YARA rules.
•	Now we create a function in which we run a loop on all the samples
