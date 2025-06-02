import os
import datetime
import win32security
from smb.SMBConnection import SMBConnection
from openpyxl import Workbook
from tqdm import tqdm
import getpass

print(
"""===========================
| FILE PERMISSION CHECKER |
===========================""")

ip_target = input("IP Target: ")
username = input("Username: ")
password = getpass.getpass("Password: ")

def decode_access_mask(access_mask):
    rights = []

    if access_mask == 0x1F01FF:
        rights.append("Full Control")
    else:
        if access_mask == 0x1301BF:
            rights.append("Modify")
        if access_mask == 0x1200A9:
            rights.append("Read & Execute")
        if access_mask == 0x120089:
            rights.append("Read")
        if access_mask == 0x100116:
            rights.append("Write")
        if access_mask == 0x20000:
            rights.append("Synchronize")
        if not rights:
            rights.append(f"Unknown ({access_mask})")

    return ', '.join(rights)

def get_permissions(file_path):
    permissions = []
    try:
        sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl:
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                sid = ace[2]
                try:
                    user, domain, _ = win32security.LookupAccountSid(None, sid)
                    account_name = f"{domain}\\{user}"
                except Exception:
                    account_name = f"SID:{sid}"
                access_mask = ace[1]
                readable_rights = decode_access_mask(access_mask)
                permissions.append(f"{account_name}: {readable_rights}")
    except Exception as e:
        permissions.append(f"Error: {str(e)}")
    
    return permissions

def main(ip, username, password):
    try:
        connect = SMBConnection(username, password, 'scanner', 'target', use_ntlm_v2=True, is_direct_tcp=True)
        if not connect.connect(ip, 445):
            print("\n❌ Could not connect to SMB (port 445).")
            return
    except Exception as e:
        if "Access Denied" in str(e) or "STATUS_ACCESS_DENIED" in str(e):
            print("\n❌ Anonymous access is not allowed on this SMB share.")
        else:
            print(f"\n❌ Failed to connect: {e}")
        return
    
    shared_folders = connect.listShares()
    
    if not shared_folders:
        print("\n❌ No shared folders found.")
        return
    
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H-%M-%S')
    output_file = f"permission_check_{ip}_{timestamp}.xlsx"
    data = []
    warnings = []
    total_items = 0

    print("\n[+] Shared folders found:")
    for share in shared_folders:
        if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL']:
            base_path = f"\\\\{ip}\\{share.name}"
            for _, _, files in os.walk(base_path):
                total_items += 1 + len(files)

    with tqdm(total=total_items, desc="Scanning", unit=" item") as pbar:
        for share in shared_folders:
            if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL']:
                print(f"  - {share.name}")
                base_path = f"\\\\{ip}\\{share.name}"
                for root, _, files in os.walk(base_path):
                    
                    # Scan folder
                    permissions = get_permissions(root)
                    if any('Everyone' in p for p in permissions):
                        warnings.append(f"⚠️ WARNING: 'Everyone' access in folder: {root}")
                    data.append([ip, root, "; ".join(permissions)])
                    pbar.update(1)
                    
                    # # Scan files
                    for file in files:
                        file_path = os.path.join(root, file)
                        permissions = get_permissions(file_path)
                        if any('Everyone' in p for p in permissions):
                            warnings.append(f"⚠️ WARNING: 'Everyone' access in file: {file_path}")
                        data.append([ip, file_path, "; ".join(permissions)])
                        pbar.update(1)

    save_to_excel(data, warnings, output_file)
    print(f"\n[+] The file is saved in: {output_file}")
    print_summary(data, warnings)
    connect.close()

def save_to_excel(data, warnings, output_file):
    wb = Workbook()
    ws = wb.active
    ws.append(["Computer IP", "Path", "Permissions"])
    for row in data:
        ws.append(row)
    if warnings:
        ws.append([])
        ws.append(["Warnings"])
        for warning in warnings:
            ws.append([warning])
    wb.save(output_file)

def print_summary(data, warnings):
    print("\n[+] Summary:")
    print(f"  Total item: {len(data)}")
    print(f"  Total warnings: {len(warnings)}")
    if warnings:
        print("[+] List of warnings:")
        for warning in warnings:
            print(f"    - {warning}")

main(ip_target, username, password)