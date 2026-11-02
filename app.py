import os               # Handles file paths, sizes, and OS-level timestamps
import datetime         # Formats timestamps into readable dates (e.g., YYYY-MM-DD)
import hashlib          # Generates MD5 and SHA-256 hashes for file integrity
import base64           # Encodes the vault encryption key into a usable format
import docx             # Reads and scrubs metadata from Word documents (.docx)
import openpyxl         # Reads and scrubs metadata from Excel spreadsheets (.xlsx)
import time             # Adds tiny delays for the progress bar animation

import tkinter as tk                    # Core library for the base window and GUI
from tkinter import filedialog, ttk     # Opens file explorer (filedialog) and builds the data table (ttk)
import customtkinter as ctk             # Provides the modern, dark-mode UI theme
from CTkMessagebox import CTkMessagebox # Creates the success, warning, and error pop-up alerts

# Third-party libraries
from PIL import Image                                               # Opens images to read dimensions or recreate them cleanly
from PIL.ExifTags import TAGS                                       # Translates raw EXIF number codes into readable text
import pikepdf                                                      # Reads and modifies PDF metadata without breaking the file
from reportlab.lib.pagesizes import letter                          # Sets the page size for the PDF audit report export
from reportlab.pdfgen import canvas                                 # Draws the text and lines for the exported PDF report
from cryptography.fernet import Fernet, InvalidToken                # Handles AES encryption and wrong password errors
from cryptography.hazmat.primitives import hashes                   # Core cryptographic math for securing passwords
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC    # Stretches the master password into a secure key

# ==========================================
# BACKEND: FORENSIC EXTRACTION ENGINE
# ==========================================
def calculate_hashes(file_path):
    """Generates MD5 and SHA-256 hashes for forensic chain of custody."""
    sha256_hash = hashlib.sha256()      # Prepares the highly secure SHA-256 calculator
    md5_hash = hashlib.md5()            # Prepares the older, widely used MD5 calculator
    
    try:
        # Opens the target file in "Read Binary" (rb) mode so we only see raw machine data
        with open(file_path, "rb") as f:
            
            # Reads the file in small 4KB (4096 bytes) chunks so large files don't crash your computer's RAM
            for byte_block in iter(lambda: f.read(4096), b""):
                
                sha256_hash.update(byte_block)      # Feeds the data chunk into the SHA-256 calculator
                md5_hash.update(byte_block)         # Feeds the data chunk into the MD5 calculator
        
        # Returns the final mathematical fingerprints as normal, readable text (hexadecimal)
        return sha256_hash.hexdigest(), md5_hash.hexdigest()
    
    except Exception as e:
        # If the file is locked, missing, or corrupted, return the error message instead of crashing
        return str(e), str(e)
    
def assess_risk_tier(tag_name):
    """Simulates a data classification engine profiling metadata tags for privacy risks."""
    tag_lower = str(tag_name).lower()

    # 1. Catch Intrinsic System Properties first (These are facts, not privacy risks)
    system_triggers = ['hash', 'size', 'name', 'os creation', 'os modification']
    if any(trigger in tag_lower for trigger in system_triggers):
        return "SYSTEM DATA"

    # 2. Evaluate actual embedded metadata for privacy risks
    high_risk_triggers = ['gps', 'latitude', 'longitude', 'serial', 'owner', 'author', 'creator']
    med_risk_triggers = ['date', 'time', 'software', 'hardware', 'make', 'model']
    
    if any(trigger in tag_lower for trigger in high_risk_triggers):
        return "HIGH RISK"
    elif any(trigger in tag_lower for trigger in med_risk_triggers):
        return "MEDIUM RISK"
    else:
        return "LOW RISK"

def extract_metadata(file_path):
    """The core engine that pulls hidden data and system properties from the target file."""
    
    # Splits the file path to isolate the extension (e.g., turns "image.jpg" into ".jpg")
    # We force it to lowercase so '.JPG' and '.jpg' are treated exactly the same
    ext = os.path.splitext(file_path)[1].lower()
    
    # Creates an empty list to store all the data we find. 
    # This list will eventually be sent directly to your UI's Treeview table.
    metadata_rows = []
    
    try:
        # Asks the Operating System for the file's raw properties (size, timestamps, etc.)
        file_stats = os.stat(file_path)

        # Converts the file size from raw bytes into kilobytes (KB) and rounds to 2 decimal places
        size_kb = round(file_stats.st_size / 1024, 2)
        
        # Converts the raw computer timestamps into readable forensic timeline formats (YYYY-MM-DD HH:MM:SS)
        # Handles Windows creation time vs Linux/Kali ctime gracefully
        birth_or_ctime = getattr(file_stats, 'st_birthtime', file_stats.st_ctime)
        create_time = datetime.datetime.fromtimestamp(birth_or_ctime).strftime('%Y-%m-%d %H:%M:%S')
        mod_time = datetime.datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        
        # Calls the hashing function we just looked at to grab the digital fingerprints
        sha256, md5 = calculate_hashes(file_path)
        
        # Packages the extracted data into rows (Risk Tier, Tag, Value) and adds them to our list
        metadata_rows.append((assess_risk_tier("SHA-256 Hash"), "SHA-256 Hash", sha256))
        metadata_rows.append((assess_risk_tier("MD5 Hash"), "MD5 Hash", md5))
        metadata_rows.append((assess_risk_tier("File Name"), "File Name", os.path.basename(file_path)))
        metadata_rows.append((assess_risk_tier("File Size"), "File Size", f"{size_kb} KB"))
        metadata_rows.append((assess_risk_tier("OS Creation Time"), "OS Creation Time", create_time))
        metadata_rows.append((assess_risk_tier("OS Modification Time"), "OS Modification Time", mod_time))

    except Exception as e:
        # If the OS refuses to give us the stats (e.g., due to permission errors), log it instead of crashing
        metadata_rows.append(("Error", "OS Stat Failure", str(e)))

    # A list of the image formats your tool is programmed to scrub and analyze
    supported_images = ['.jpg', '.jpeg', '.png', '.tiff', '.tif', '.webp', '.bmp']
    
    try:
        # ==========================================
        # 1. IMAGE FORENSICS (JPEG, PNG, TIFF, etc.)
        # ==========================================
        if ext in supported_images:
            # Safely open the image using the Pillow (PIL) library
            with Image.open(file_path) as img:
                
                # Extract basic physical properties of the image
                metadata_rows.append(("Dimensions", "Resolution", f"{img.width} x {img.height} pixels"))
                metadata_rows.append(("Dimensions", "Color Mode", img.mode))
                
                # _getexif() pulls the hidden EXIF dictionary (which often contains GPS, Camera Model, Dates)
                exif_data = img.getexif()
                
                if exif_data:
                    # Loop through every piece of hidden EXIF data found
                    for tag_id, value in exif_data.items():
                        
                        # Translates raw computer numbers (like '271') into readable tags (like 'Make' or 'Model')
                        tag_name = TAGS.get(tag_id, tag_id)
                        
                        # If the data is in raw machine bytes, decode it into readable human text
                        if isinstance(value, bytes):
                            value = value.decode(errors='replace').strip()
                            
                        metadata_rows.append((assess_risk_tier(tag_name), str(tag_name), str(value)))
                else:
                    # If the image was already scrubbed or lacks EXIF, note it in the table
                    metadata_rows.append(("Embedded EXIF", "Status", "No EXIF data found"))
                    
        # ==========================================
        # 2. PDF FORENSICS (.pdf)
        # ==========================================
        elif ext == '.pdf':
            # Open the PDF using pikepdf, which reads the file deeply without corrupting its structure
            with pikepdf.open(file_path) as pdf:
                metadata_rows.append((assess_risk_tier("Total Pages"), "Total Pages", str(len(pdf.pages))))
                
                # Pulls the hidden document properties dictionary (docinfo)
                meta = pdf.docinfo
                
                if meta:
                    for key, value in meta.items():
                        # PDF keys usually start with a slash (like "/Author"). lstrip('/') cleans that up.
                        metadata_rows.append((assess_risk_tier(key), key, value))
                else:
                    metadata_rows.append(("Embedded Document", "Status", "No DocInfo found"))
                    
        # ==========================================
        # 3. WORD DOCUMENT FORENSICS (.docx)
        # ==========================================
        elif ext == '.docx':
            # Opens the Word document structure without needing Microsoft Word installed
            doc = docx.Document(file_path)
            
            # Targets the 'core_properties' XML hidden inside the .docx container
            core_props = doc.core_properties
            
            # Extracts human-centric data: Who made it, who last saved it, and when
            metadata_rows.append(("Document Properties", "Author", str(core_props.author or "Unspecified")))
            metadata_rows.append(("Document Properties", "Last Modified By", str(core_props.last_modified_by or "Unspecified")))
            
            # Revision number is critical: it proves how many times the document was edited
            metadata_rows.append(("Document Properties", "Revision Number", str(core_props.revision)))
            metadata_rows.append(("Document Properties", "Created Time", str(core_props.created)))

        # ==========================================
        # 4. EXCEL SPREADSHEET FORENSICS (.xlsx)
        # ==========================================
        elif ext == '.xlsx':
            # Loads the Excel workbook specifically targeting its properties, not the cell data
            wb = openpyxl.load_workbook(file_path)
            props = wb.properties
            
            # Extracts corporate-level tracking data embedded by Excel
            metadata_rows.append(("Spreadsheet Properties", "Creator", str(props.creator)))
            metadata_rows.append(("Spreadsheet Properties", "Last Modified By", str(props.lastModifiedBy)))
            metadata_rows.append(("Spreadsheet Properties", "Created Time", str(props.created)))

    except Exception as e:
        # If the file is corrupted, encrypted/password-protected, or unsupported,
        # we log the exact error to the table instead of letting the app crash.
        metadata_rows.append(("Error", "Format Specific Parsing Failed", str(e)))

    # Finally, hand the fully populated list of metadata back to the GUI's Treeview table
    return metadata_rows

# ==========================================
# BACKEND: FORENSIC SANITIZATION ENGINE
# ==========================================
def sanitize_file(file_path, replacement_text=""):
    """
    Scrubs or overwrites hidden metadata from the target file.
    Creates a safe copy rather than destroying the original evidence.
    """
    
    # --- DEFENSIVE PROGRAMMING FAIL-SAFE ---
    # If the system accidentally passes a tuple instead of a string, grab the first string inside it!
    if isinstance(file_path, tuple):
        file_path = file_path[0]
        
    # Isolate the file extension and folder location
    ext = os.path.splitext(file_path)[1].lower()
    dir_name = os.path.dirname(file_path)
    base_name = os.path.basename(file_path)
    
    # FORENSIC BEST PRACTICE: Never modify original evidence! 
    # We create a brand new file with a "sanitized_" prefix.
    new_file_path = os.path.join(dir_name, f"sanitized_{base_name}")
    
    supported_images = ['.jpg', '.jpeg', '.png', '.tiff', '.tif', '.webp', '.bmp']
    
    try:
        # ==========================================
        # 1. IMAGE SANITIZATION
        # ==========================================
        if ext in supported_images:
            # Open the contaminated image
            with Image.open(file_path) as img:
                
                # To completely strip EXIF data without corrupting the picture,
                # we extract the raw pixel data and paste it onto a brand new, blank canvas.
                # Pastes pixel canvas directly without dumping millions of tuples into Python RAM
                clean_image = Image.new(img.mode, img.size)
                clean_image.paste(img)
                clean_image.save(new_file_path)

        # ==========================================
        # 2. PDF SANITIZATION
        # ==========================================
        elif ext == '.pdf':
            # Open the PDF safely using pikepdf
            with pikepdf.open(file_path) as pdf:
                
                # If the user typed an alias (like "REDACTED") in the UI prompt:
                if replacement_text:
                    # Overwrite the core identifying tags with the custom alias
                    pdf.docinfo['/Author'] = replacement_text
                    pdf.docinfo['/Creator'] = replacement_text
                    pdf.docinfo['/Title'] = replacement_text
                    pdf.docinfo['/Producer'] = replacement_text
                
                # If the user left the prompt blank:
                else:
                    # Completely delete the entire hidden dictionary from the PDF structure
                    if hasattr(pdf, 'docinfo'):
                        del pdf.docinfo
                    # Wipe embedded XML-based XMP metadata streams
                    with pdf.open_metadata() as meta:
                         meta.clear()

                # Save the scrubbed PDF to the new file path
                pdf.save(new_file_path)
                
        # ==========================================
        # 3. WORD DOCUMENT SANITIZATION (.docx)
        # ==========================================
        elif ext == '.docx':
            # Open the Word document structure
            doc = docx.Document(file_path)
            core_props = doc.core_properties
            
            # Overwrite the identifying data with the user's custom alias
            core_props.author = replacement_text
            core_props.last_modified_by = replacement_text
            
            # If the user didn't provide an alias, we inject a default forensic watermark.
            # This proves the document was processed by a security tool.
            core_props.comments = "SANITIZED BY HADI'S AUDITOR" if not replacement_text else replacement_text
            
            # Save the scrubbed Word document as a new file
            doc.save(new_file_path)
            
        # ==========================================
        # 4. EXCEL SPREADSHEET SANITIZATION (.xlsx)
        # ==========================================
        elif ext == '.xlsx':
            # Open the Excel workbook
            wb = openpyxl.load_workbook(file_path)
            props = wb.properties
            
            # Overwrite the creator and last modified fields
            props.creator = replacement_text
            props.lastModifiedBy = replacement_text
            
            # Inject the forensic watermark into the description field
            props.description = "SANITIZED BY HADI'S AUDITOR" if not replacement_text else replacement_text
            
            # Save the scrubbed Excel file as a new file
            wb.save(new_file_path)
            
        # ==========================================
        # 5. UNSUPPORTED FILES & ERROR HANDLING
        # ==========================================
        else:
            # If the user bypassed the UI and tried to sanitize an unsupported file (.txt, .exe)
            # return 'False' to trigger the error popup in the UI.
            return False, f"Sanitization for {ext} is not supported."
        
        # If the code reaches this line, the sanitization was 100% successful!
        # Return 'True' and the location of the safe file so the UI can display it.
        return True, new_file_path
    except Exception as e:
        return False, str(e)

# ==========================================
# BACKEND: SECURE VAULT ENGINE
# ==========================================
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_to_vault(file_path, password):
    try:
        salt = os.urandom(16)
        key = derive_key(password, salt)
        cipher = Fernet(key)
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
            
        encrypted_data = cipher.encrypt(file_data)
        vault_path = file_path + ".vault"
        
        with open(vault_path, 'wb') as f:
            f.write(salt + encrypted_data)
            
        return True, vault_path
    except Exception as e:
        return False, str(e)

def decrypt_from_vault(vault_path, password):
    try:
        with open(vault_path, 'rb') as f:
            salt = f.read(16) 
            encrypted_data = f.read() 
            
        key = derive_key(password, salt)
        cipher = Fernet(key)
        decrypted_data = cipher.decrypt(encrypted_data)
        
        base_name = vault_path.removesuffix(".vault") if vault_path.endswith(".vault") else vault_path
        name, ext = os.path.splitext(base_name)
        original_path = f"{name}_UNLOCKED{ext}"
        
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)
            
        return True, original_path
    except InvalidToken:
        return False, "Access Denied: Incorrect Master Password."
    except Exception as e:
        return False, str(e)

# ==========================================
# FRONTEND / UI ACTIONS
# ==========================================
current_active_file = ""

def open_file_explorer():
    global current_active_file
    file_path = filedialog.askopenfilename(
        title="Select Forensic Target File",
        filetypes=[("All Supported Formats", "*.jpg *.jpeg *.png *.tiff *.webp *.bmp *.pdf *.docx *.xlsx")]
    )
    if not file_path: return 
    
    current_active_file = file_path
    log_system_event(f"Ingesting target file: {os.path.basename(file_path)}")
    
    # --- THIS IS THE CRITICAL LINE THAT PREVENTS DUPLICATES ---
    for row in tree.get_children(): tree.delete(row)
        
    extracted_data = extract_metadata(file_path)
    for item in extracted_data:
        risk_level = item[0] 
        tree.insert("", tk.END, values=item, tags=(risk_level,))
    
    update_risk_guidance(extracted_data)
    lbl_file_status.configure(text=f"Target: {os.path.basename(file_path)}")

def trigger_sanitization():
    if not current_active_file:
        CTkMessagebox(title="Warning", message="Please audit a file first.", icon="warning")
        return
        
    dialog = ctk.CTkInputDialog(text="Enter replacement alias:\n(Leave blank to empty fields)", title="Sanitization Settings")
    custom_text = dialog.get_input()
    
    if custom_text is None: 
        return 
    if custom_text == "":
        custom_text = ""
        
    ext = os.path.splitext(current_active_file)[1].lower()
    default_filename = f"sanitized_{os.path.basename(current_active_file)}"
    
    save_path = filedialog.asksaveasfilename(
        title="Select Output Folder and File Name",
        initialfile=default_filename,
        defaultextension=ext,
        filetypes=[(f"{ext[1:].upper()} File", f"*{ext}"), ("All Files", "*.*")]
    )
    
    if not save_path:
        return

    progress_bar.configure(mode="determinate")
    progress_bar.set(0)
    log_system_event("Initiating metadata sanitization sequence...")
    
    progress_bar.set(0.2) 
    window.update()      
    time.sleep(0.3)       
        
    success, result = sanitize_file(current_active_file, output_path=save_path, replacement_text=custom_text)
    
    progress_bar.set(0.6) 
    window.update()
    time.sleep(0.3)       
    
    if success:
        # Calculate post-sanitization SHA-256 hash for chain of custody
        sanitized_sha256, _ = calculate_hashes(result)
        
        log_system_event(f"Sanitization successful. Saved to: {result}")
        log_system_event(f"Post-Sanitization SHA-256 Hash: {sanitized_sha256}")
        
        extracted_data = extract_metadata(result)
        
        for row in tree.get_children(): 
            tree.delete(row)
            
        for item in extracted_data:
            risk_level = item[0] 
            tree.insert("", tk.END, values=item, tags=(risk_level,))
            
        # Update the right-side risk guidance panel
        update_risk_guidance(extracted_data)
            
        progress_bar.set(1.0) 
        window.update()
        time.sleep(0.2)       
        
        CTkMessagebox(
            title="Success", 
            message=f"File scrubbed and saved to:\n{result}\n\nSHA-256 Verified:\n{sanitized_sha256[:32]}...", 
            icon="check"
        )
        progress_bar.set(0)
    else:
        CTkMessagebox(title="Error", message=result, icon="cancel")
        progress_bar.set(0)

def trigger_vault_encryption():
    if not current_active_file:
        CTkMessagebox(title="Warning", message="Please audit a file first.", icon="warning")
        return
        
    dialog = ctk.CTkInputDialog(text="Enter Master Password to lock file:", title="Secure Vault")
    password = dialog.get_input()
    if not password: return 
        
    success, result = encrypt_to_vault(current_active_file, password)
    if success:
        CTkMessagebox(title="Vault Success", message=f"File locked securely with PBKDF2 to:\n{result}", icon="check")
    else:
        CTkMessagebox(title="Error", message=result, icon="cancel")

def trigger_vault_decryption():
    vault_path = filedialog.askopenfilename(
        title="Select Vault File to Unlock",
        filetypes=[("Encrypted Vault", "*.vault")]
    )
    if not vault_path: return
    
    dialog = ctk.CTkInputDialog(text="Enter Master Password to unlock:", title="Secure Vault")
    password = dialog.get_input()
    if not password: return
    
    success, result = decrypt_from_vault(vault_path, password)
    if success:
        CTkMessagebox(title="Unlock Success", message=f"File decrypted successfully to:\n{result}", icon="check")
    else:
        CTkMessagebox(title="Error", message=result, icon="cancel")

def export_pdf_report():
    if not tree.get_children():
        CTkMessagebox(title="Warning", message="No data available. Please audit a file first.", icon="warning")
        return
        
    save_path = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF Document", "*.pdf")],
        title="Export Forensic PDF Audit Report"
    )
    if not save_path: return
    
    try:
        c = canvas.Canvas(save_path, pagesize=letter)
        width, height = letter
        
        def draw_headers(canvas_obj, y_pos):
            canvas_obj.setFont("Helvetica-Bold", 16)
            canvas_obj.drawString(50, y_pos, "FORENSIC METADATA AUDIT REPORT")
            canvas_obj.setFont("Helvetica", 10)
            canvas_obj.drawString(50, y_pos - 20, f"Generated On: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            canvas_obj.drawString(50, y_pos - 35, f"Target Source File: {os.path.basename(current_active_file)}")
            canvas_obj.line(50, y_pos - 45, width - 50, y_pos - 45)
            canvas_obj.setFont("Helvetica-Bold", 11)
            canvas_obj.drawString(50, y_pos - 70, "Classification")
            canvas_obj.drawString(180, y_pos - 70, "Metadata Property")
            canvas_obj.drawString(340, y_pos - 70, "Extracted Value")
            canvas_obj.line(50, y_pos - 75, width - 50, y_pos - 75)
            return y_pos - 95
        
        y_position = draw_headers(c, height - 50)
        c.setFont("Helvetica", 10)
        
        for row_id in tree.get_children():
            if y_position < 50:
                c.showPage()
                y_position = draw_headers(c, height - 50)
                c.setFont("Helvetica", 10)
                
            category, tag, val = tree.item(row_id)['values']
            clean_val = str(val)[:50] + "..." if len(str(val)) > 50 else str(val)
            
            c.drawString(50, y_position, str(category))
            c.drawString(180, y_position, str(tag))
            c.drawString(340, y_position, clean_val)
            y_position -= 20 
            
        c.save()
        CTkMessagebox(title="Success", message=f"Professional PDF Report successfully generated:\n{save_path}", icon="check")
        
    except Exception as e:
        CTkMessagebox(title="Export Error", message=f"Could not generate PDF: {str(e)}", icon="cancel")

# ==========================================
# CENTRALIZED THEME PALETTE (Catppuccin/Cyber Slate)
# ==========================================
THEME = {
    # Surfaces & Backgrounds
    "BG_DARK": "#0F111A",        # Main Window Base
    "SURFACE_MAIN": "#1A1C29",   # Cards & Containers
    "SURFACE_ALT": "#24273A",    # Toolbar & Table Headings
    
    # Primary & Secondary Accents
    "ACCENT_PRIMARY": "#00E5FF", # Cyber Cyan (Main Action)
    "ACCENT_HOVER": "#00B4D8",   # Hover state for primary accent
    "BTN_SECONDARY": "#2D3142",  # Subtle Dark Slate for utility buttons
    "BTN_SEC_HOVER": "#3F445B",  # Hover state for utility buttons
    "BTN_EXPORT": "#2E7D32",     # Forest Green (Export PDF)
    "BTN_EXP_HOVER": "#1B5E20",
    
    # Text Hierarchy
    "TEXT_MAIN": "#E2E8F0",      # Pure readability text
    "TEXT_MUTED": "#94A3B8",     # Subtitles & inactive labels
    "TEXT_ACCENT": "#00E5FF",    # Key highlight headers
    
    # Risk Tier Badges (Desaturated for professional look)
    "RISK_HIGH": "#FF5252",      # Muted Red
    "RISK_MED": "#FFB74D",       # Warm Amber
    "RISK_LOW": "#4DD0E1",       # Soft Teal
    "RISK_SYSTEM": "#7E57C2",    # Deep Purple
    "RISK_CLEAN": "#66BB6A"      # Soft Mint
}

def sort_treeview_column(tree, col, reverse):
    """
    Sorts Treeview rows when a user clicks a column header.
    Sorts 'Classification Tier' by forensic risk priority (HIGH > MEDIUM > LOW > SYSTEM).
    Sorts other columns alphabetically.
    """
    # Custom priority ranking for forensic risk tier sorting
    risk_priority = {
        "HIGH RISK": 1,
        "MEDIUM RISK": 2,
        "LOW RISK": 3,
        "SYSTEM DATA": 4,
        "SANITIZED": 5
    }

    # Fetch all row values for the target column
    items = [(tree.set(k, col), k) for k in tree.get_children('')]

    # Apply sorting logic
    if col == 'category':
        # Sort by risk urgency rank
        items.sort(key=lambda x: (risk_priority.get(x[0], 99), x[0]), reverse=reverse)
    else:
        # Standard case-insensitive alphabetical sort
        items.sort(key=lambda x: str(x[0]).lower(), reverse=reverse)

    # Move rows into new sorted order
    for index, (val, k) in enumerate(items):
        tree.move(k, '', index)

    # Column header labels
    headers = {
        'category': 'Classification Tier',
        'metadata_tag': 'Metadata Property Tag',
        'extracted_value': 'Extracted Forensics Data Value'
    }
    
    arrow = " ▲" if not reverse else " ▼"

    # Reset all column header texts
    for c in headers:
        tree.heading(c, text=headers[c], command=lambda _c=c: sort_treeview_column(tree, _c, False))

    # Apply directional arrow to active header and set reverse flag for next click
    tree.heading(col, text=headers[col] + arrow, command=lambda: sort_treeview_column(tree, col, not reverse))

def generate_risk_advisory(extracted_data):
    """
    Analyzes extracted metadata rows and generates human-readable risk explanations
    and recommended mitigation actions for the UI panel.
    """
    high_count = sum(1 for item in extracted_data if item[0] == "HIGH RISK")
    med_count = sum(1 for item in extracted_data if item[0] == "MEDIUM RISK")
    low_count = sum(1 for item in extracted_data if item[0] == "LOW RISK")
    is_sanitized = any(item[0] == "SANITIZED" for item in extracted_data)

    explanations = []
    actions = []

    if is_sanitized:
        status_text = "FILE IS SANITIZED"
        badge_color = THEME["RISK_CLEAN"]
        explanations.append("✔ All sensitive embedded EXIF, docinfo, and user properties have been scrubbed.")
        explanations.append("✔ Original digital fingerprint has been isolated to preserve evidence.")
        actions.append("• Safe to share on public platforms or transmit via email.")
        actions.append("• Export a PDF report to record chain-of-custody proof.")
        return status_text, badge_color, high_count, med_count, low_count, "\n".join(explanations), "\n".join(actions)

    # High Risk Evaluation
    if high_count > 0:
        status_text = "HIGH RISK DETECTED"
        badge_color = THEME["RISK_HIGH"]
        explanations.append("⚠ Precise GPS/Location tags found: Exposes physical whereabouts.")
        explanations.append("⚠ Hardware/Device Serial Numbers found: Allows cross-photo tracking.")
        actions.append("1. Click 'Sanitize Data' to strip GPS coordinates and hardware IDs.")
        actions.append("2. Use 'Lock Vault' (AES-256) if storing original evidence safely.")
    # Medium Risk Evaluation
    elif med_count > 0:
        status_text = "MEDIUM RISK DETECTED"
        badge_color = THEME["RISK_MED"]
        explanations.append("⚠ Camera make/model or software history tags detected.")
        explanations.append("⚠ Author/Creator metadata found: Reveals user identity/username.")
        actions.append("1. Click 'Sanitize Data' to replace author info with a custom alias.")
        actions.append("2. Export a forensic PDF report prior to file distribution.")
    # Low Risk / Clean
    else:
        status_text = "LOW RISK / CLEAN"
        badge_color = THEME["RISK_LOW"]
        explanations.append("ℹ Minimal or no embedded metadata vectors detected.")
        explanations.append("ℹ Only basic system properties (file size, OS timestamps) present.")
        actions.append("• File is low-risk for general distribution.")
        actions.append("• No immediate sanitization required.")

    return status_text, badge_color, high_count, med_count, low_count, "\n".join(explanations), "\n".join(actions)

def update_risk_guidance(extracted_data):
    """Refreshes the right-side risk panel with live metrics and advice."""
    status_text, badge_color, high, med, low, explanation, recommendation = generate_risk_advisory(extracted_data)

    # Update Status Badges (Header & Panel)
    panel_risk_badge.configure(text=f" STATUS: {status_text} ", fg_color=badge_color, text_color="#0F111A" if badge_color != THEME["SURFACE_ALT"] else THEME["TEXT_MUTED"])
    lbl_risk_badge.configure(text=f" STATUS: {status_text} ", fg_color=badge_color, text_color="#0F111A" if badge_color != THEME["SURFACE_ALT"] else THEME["TEXT_MUTED"])

    # Update Counter KPIs
    lbl_high_kpi.configure(text=f"High: {high}")
    lbl_med_kpi.configure(text=f"Med: {med}")
    lbl_low_kpi.configure(text=f"Low: {low}")

    # Refresh Textboxes
    txt_explanation.delete("1.0", tk.END)
    txt_explanation.insert("1.0", explanation)

    txt_recommendations.delete("1.0", tk.END)
    txt_recommendations.insert("1.0", recommendation)

# ==========================================
# MAIN APPLICATION APP LAYOUT
# ==========================================
ctk.set_appearance_mode("dark")

ctk.set_widget_scaling(1.25)

window = ctk.CTk()
window.title("Automated Forensic Metadata Auditor & Cryptographic Vault")
window.geometry("1180x750")
window.configure(fg_color=THEME["BG_DARK"])

if os.path.exists("GL.ico"):
    window.iconbitmap("GL.ico")

# ------------------------------------------
# 1. HEADER BRANDING & KPI PANEL
# ------------------------------------------
header_frame = ctk.CTkFrame(window, corner_radius=10, fg_color=THEME["SURFACE_MAIN"])
header_frame.pack(fill="x", padx=15, pady=(15, 10))

title_label = ctk.CTkLabel(
    header_frame, 
    text="FORENSIC METADATA AUDITOR", 
    font=("Segoe UI", 16, "bold"), 
    text_color=THEME["TEXT_ACCENT"]
)
title_label.pack(side="left", padx=15, pady=12)

status_container = ctk.CTkFrame(header_frame, fg_color="transparent")
status_container.pack(side="right", padx=15)

lbl_file_status = ctk.CTkLabel(
    status_container, 
    text="Target: No File Ingested", 
    font=("Segoe UI", 11), 
    text_color=THEME["TEXT_MUTED"]
)
lbl_file_status.pack(side="left", padx=10)

lbl_risk_badge = ctk.CTkLabel(
    status_container, 
    text=" STATUS: IDLE ", 
    font=("Segoe UI", 11, "bold"), 
    fg_color=THEME["SURFACE_ALT"], 
    text_color=THEME["TEXT_MAIN"], 
    corner_radius=6
)
lbl_risk_badge.pack(side="left", padx=5)

# ------------------------------------------
# 2. STREAMLINED ACTION TOOLBAR
# ------------------------------------------
toolbar_frame = ctk.CTkFrame(window, corner_radius=8, fg_color=THEME["SURFACE_MAIN"])
toolbar_frame.pack(fill="x", padx=15, pady=(0, 10))

# Standardized button geometry
btn_base = {
    "corner_radius": 6, 
    "font": ("Segoe UI", 11, "bold"), 
    "height": 34,
    "text_color": THEME["TEXT_MAIN"]
}

# Primary Action (Cyan Highlight)
upload_btn = ctk.CTkButton(
    toolbar_frame, 
    text="📁 Ingest File", 
    command=open_file_explorer, 
    fg_color=THEME["ACCENT_PRIMARY"], 
    hover_color=THEME["ACCENT_HOVER"], 
    text_color="#0F111A", 
    **{k: v for k, v in btn_base.items() if k != "text_color"}
)
upload_btn.pack(side="left", padx=8, pady=8)

# Secondary Utility Actions (Unified Dark Slate Buttons)
sanitize_btn = ctk.CTkButton(
    toolbar_frame, 
    text="🧹 Sanitize Data", 
    command=trigger_sanitization, 
    fg_color=THEME["BTN_SECONDARY"], 
    hover_color=THEME["BTN_SEC_HOVER"], 
    **btn_base
)
sanitize_btn.pack(side="left", padx=4)

vault_btn = ctk.CTkButton(
    toolbar_frame, 
    text="🔒 Lock Vault", 
    command=trigger_vault_encryption, 
    fg_color=THEME["BTN_SECONDARY"], 
    hover_color=THEME["BTN_SEC_HOVER"], 
    **btn_base
)
vault_btn.pack(side="left", padx=4)

decrypt_btn = ctk.CTkButton(
    toolbar_frame, 
    text="🔓 Unlock Vault", 
    command=trigger_vault_decryption, 
    fg_color=THEME["BTN_SECONDARY"], 
    hover_color=THEME["BTN_SEC_HOVER"], 
    **btn_base
)
decrypt_btn.pack(side="left", padx=4)

# Dedicated Export Action (Forest Green)
pdf_btn = ctk.CTkButton(
    toolbar_frame, 
    text="📄 Export PDF", 
    command=export_pdf_report, 
    fg_color=THEME["BTN_EXPORT"], 
    hover_color=THEME["BTN_EXP_HOVER"], 
    **btn_base
)
pdf_btn.pack(side="left", padx=4)

# Progress Bar
progress_bar = ctk.CTkProgressBar(window, mode="determinate", height=3, progress_color=THEME["ACCENT_PRIMARY"])
progress_bar.pack(fill="x", padx=15, pady=(0, 10))
progress_bar.set(0)

# ------------------------------------------
# 3. AUDIT DATA & RISK INSIGHT SPLIT CONTAINER
# ------------------------------------------
content_container = ctk.CTkFrame(window, fg_color="transparent")
content_container.pack(fill="both", expand=True, padx=15, pady=(0, 10))

# --- LEFT COLUMN: TREEVIEW TABLE (Flex Expand) ---
table_frame = ctk.CTkFrame(content_container, corner_radius=10, fg_color=THEME["SURFACE_MAIN"])
table_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))

style = ttk.Style()
style.theme_use("default")
style.configure(
    "Treeview", 
    background=THEME["SURFACE_MAIN"], 
    foreground=THEME["TEXT_MAIN"], 
    fieldbackground=THEME["SURFACE_MAIN"], 
    borderwidth=0,
    rowheight=26,
    font=("Segoe UI", 10)
)
style.map('Treeview', background=[('selected', THEME["SURFACE_ALT"])], foreground=[('selected', THEME["ACCENT_PRIMARY"])])
style.configure(
    "Treeview.Heading", 
    background=THEME["SURFACE_ALT"], 
    foreground=THEME["TEXT_ACCENT"], 
    relief="flat", 
    font=("Segoe UI", 10, "bold")
)

columns = ('category', 'metadata_tag', 'extracted_value')
tree = ttk.Treeview(table_frame, columns=columns, show='headings')

tree.heading('category', text='Classification Tier', command=lambda: sort_treeview_column(tree, 'category', False))
tree.heading('metadata_tag', text='Metadata Property Tag', command=lambda: sort_treeview_column(tree, 'metadata_tag', False))
tree.heading('extracted_value', text='Extracted Forensics Data Value', command=lambda: sort_treeview_column(tree, 'extracted_value', False))

tree.column('category', width=140, anchor="w")
tree.column('metadata_tag', width=200, anchor="w")
tree.column('extracted_value', width=380, anchor="w")

tree.tag_configure('HIGH RISK', foreground=THEME["RISK_HIGH"], font=("Segoe UI", 10, "bold"))
tree.tag_configure('MEDIUM RISK', foreground=THEME["RISK_MED"])
tree.tag_configure('LOW RISK', foreground=THEME["RISK_LOW"])
tree.tag_configure('SYSTEM DATA', foreground=THEME["RISK_SYSTEM"])
tree.tag_configure('SANITIZED', foreground=THEME["RISK_CLEAN"], font=("Segoe UI", 10, "bold"))

scrollbar = ctk.CTkScrollbar(table_frame, command=tree.yview)
tree.configure(yscroll=scrollbar.set)

tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
scrollbar.pack(side="right", fill="y", padx=10, pady=10)

# --- RIGHT COLUMN: RISK ANALYSIS & GUIDANCE CARD (Fixed 320px) ---
guidance_panel = ctk.CTkFrame(content_container, width=320, corner_radius=10, fg_color=THEME["SURFACE_MAIN"])
guidance_panel.pack(side="right", fill="both", expand=False)
guidance_panel.pack_propagate(False)  # Keep fixed panel width

# Card Header
lbl_panel_title = ctk.CTkLabel(
    guidance_panel, 
    text="🛡️ RISK ASSESSMENT & ADVISORY", 
    font=("Segoe UI", 11, "bold"), 
    text_color=THEME["TEXT_ACCENT"]
)
lbl_panel_title.pack(anchor="w", padx=15, pady=(15, 10))

# Dynamic Risk Overall Badge
panel_risk_badge = ctk.CTkLabel(
    guidance_panel, 
    text="STATUS: NO FILE INGESTED", 
    font=("Segoe UI", 11, "bold"), 
    fg_color=THEME["SURFACE_ALT"], 
    text_color=THEME["TEXT_MUTED"], 
    corner_radius=6,
    height=28
)
panel_risk_badge.pack(fill="x", padx=15, pady=(0, 10))

# Counter KPI Metrics Grid
kpi_frame = ctk.CTkFrame(guidance_panel, fg_color=THEME["BG_DARK"], corner_radius=8)
kpi_frame.pack(fill="x", padx=15, pady=(0, 10))

lbl_high_kpi = ctk.CTkLabel(kpi_frame, text="High: 0", font=("Segoe UI", 10, "bold"), text_color=THEME["RISK_HIGH"])
lbl_high_kpi.pack(side="left", expand=True, pady=6)

lbl_med_kpi = ctk.CTkLabel(kpi_frame, text="Med: 0", font=("Segoe UI", 10, "bold"), text_color=THEME["RISK_MED"])
lbl_med_kpi.pack(side="left", expand=True, pady=6)

lbl_low_kpi = ctk.CTkLabel(kpi_frame, text="Low: 0", font=("Segoe UI", 10, "bold"), text_color=THEME["RISK_LOW"])
lbl_low_kpi.pack(side="left", expand=True, pady=6)

# Section 1: Threat Explanation
lbl_exp_heading = ctk.CTkLabel(guidance_panel, text="Threat Breakdown:", font=("Segoe UI", 10, "bold"), text_color=THEME["TEXT_MAIN"])
lbl_exp_heading.pack(anchor="w", padx=15, pady=(5, 2))

txt_explanation = ctk.CTkTextbox(
    guidance_panel, 
    height=110, 
    font=("Segoe UI", 9), 
    text_color=THEME["TEXT_MUTED"], 
    fg_color=THEME["BG_DARK"], 
    corner_radius=6,
    wrap="word"
)
txt_explanation.pack(fill="x", padx=15, pady=(0, 10))
txt_explanation.insert("1.0", "Ingest a target file to analyze metadata threat vectors...")

# Section 2: Recommended Remediation Actions
lbl_act_heading = ctk.CTkLabel(guidance_panel, text="Recommended Action:", font=("Segoe UI", 10, "bold"), text_color=THEME["TEXT_ACCENT"])
lbl_act_heading.pack(anchor="w", padx=15, pady=(5, 2))

txt_recommendations = ctk.CTkTextbox(
    guidance_panel, 
    height=120, 
    font=("Segoe UI", 9), 
    text_color=THEME["TEXT_MAIN"], 
    fg_color=THEME["BG_DARK"], 
    corner_radius=6,
    wrap="word"
)
txt_recommendations.pack(fill="both", expand=True, padx=15, pady=(0, 15))
txt_recommendations.insert("1.0", "Awaiting file audit...")

# ------------------------------------------
# 4. CONSOLE LOG DRAWER
# ------------------------------------------
terminal_log = ctk.CTkTextbox(
    window, 
    height=85, 
    font=("Consolas", 11), 
    text_color=THEME["RISK_CLEAN"], 
    fg_color=THEME["BG_DARK"], 
    border_color=THEME["SURFACE_ALT"], 
    border_width=1,
    corner_radius=8
)
terminal_log.pack(fill="x", padx=15, pady=(0, 15))
terminal_log.insert(tk.END, ">>> System initialized with unified theme palette. Ready for ingestion...\n")

def log_system_event(message):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    terminal_log.insert(tk.END, f">>> [{timestamp}] {message}\n")
    terminal_log.see(tk.END)

window.mainloop()