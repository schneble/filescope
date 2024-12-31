<h1 align="center">
 Filescope
</h1>
 <p align="center">A file analyzer developed during the creation of GoSeek Guard to improve comprehension of file integrity, multithreaded environments, and GUI design.</p>
<p align="center">
<img width="440" alt="brupdate-4" src="https://github.com/user-attachments/assets/c224237d-ab79-4c03-92db-f813b3e11de2" />
</p>

## Filescope use:

File Integrity Checking:
- The computed SHA-256 hashes can be used to verify the integrity of files by comparing the hashes against expected values.
  
Auditing and Inventory:
- Helps generate an inventory of files, including their sizes and hashes.
  
Security and Malware Analysis:
- Although basic, the hashing functionality can be extended to detect known malicious files by comparing their hashes against a database of known malware hashes.

## How it works:

Directory Selection:
- The user selects a directory using a file dialog.
- The chosen path is displayed in the GUI.

Scanning Process:
- The scanner traverses all subdirectories and files in the selected directory using os.walk().
- For each file:
    - It computes the SHA-256 hash using the hashlib library.
    - It retrieves the file size.
    - It formats these details into a readable report.
      
Progress Updates:
- A progress bar visually indicates the scanning progress.
- The text area displays real-time results, including the file's path, size, and hash.
  
Multithreading:
- Scanning runs in a separate thread, keeping the GUI responsive during the operation.
  
Stop Functionality:
- Users can halt the scan mid-operation by pressing the "Stop Scan" button.


  
