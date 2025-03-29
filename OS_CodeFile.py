import os
import hashlib
import json
import base64
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import re
import uuid
import smtplib
import random
import string
from datetime import datetime

# Configuration
CONFIG_FILE = "system_config.json"
USER_DB = "users.json"
FILE_DB = "files.json"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_FILENAME_LENGTH = 255
BUFFER_OVERFLOW_THRESHOLD = 1000000  # 1MB data in single operation

class SecureFileSystem:
    def __init__(self):
        self.current_user = None
        self.session_key = None
        self.initialize_system()
        
    def initialize_system(self):
        """Initialize system files and directories"""
        if not os.path.exists("secure_storage"):
            os.makedirs("secure_storage")
            
        if not os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'w') as f:
                json.dump({
                    "system_key": Fernet.generate_key().decode(),
                    "password_salt": os.urandom(16).hex(),
                    "2fa_enabled": True
                }, f)
                
        if not os.path.exists(USER_DB):
            with open(USER_DB, 'w') as f:
                json.dump({}, f)
                
        if not os.path.exists(FILE_DB):
            with open(FILE_DB, 'w') as f:
                json.dump({}, f)
    
    def load_config(self):
        """Load system configuration"""
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    
    def save_config(self, config):
        """Save system configuration"""
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
    
    def hash_password(self, password, salt=None):
        """Secure password hashing with PBKDF2"""
        if salt is None:
            config = self.load_config()
            salt = bytes.fromhex(config["password_salt"])
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()
    
    def generate_2fa_code(self):
        """Generate a 6-digit 2FA code"""
        return ''.join(random.choices(string.digits, k=6))
    
    def send_2fa_email(self, email, code):
        """Simulate sending 2FA code to email"""
        print(f"[DEBUG] 2FA code for {email}: {code}")  # In real system, send email
        # Example of real implementation:
        """
        try:
            with smtplib.SMTP('smtp.example.com', 587) as server:
                server.starttls()
                server.login('your_email@example.com', 'password')
                message = f"Subject: Your 2FA Code\n\nYour verification code is: {code}"
                server.sendmail('your_email@example.com', email, message)
        except Exception as e:
            print(f"Failed to send 2FA email: {e}")
        """
    
    def register_user(self, username, password, email=None):
        """Register a new user"""
        if not self.validate_username(username):
            return False, "Invalid username"
            
        if not self.validate_password(password):
            return False, "Password doesn't meet requirements"
            
        with open(USER_DB, 'r') as f:
            users = json.load(f)
            
        if username in users:
            return False, "Username already exists"
            
        hashed_pw = self.hash_password(password)
        user_data = {
            "password_hash": hashed_pw,
            "email": email,
            "2fa_enabled": False,
            "files": []
        }
        
        users[username] = user_data
        
        with open(USER_DB, 'w') as f:
            json.dump(users, f)
            
        return True, "User registered successfully"
    
    def login(self, username, password):
        """Authenticate user with password"""
        with open(USER_DB, 'r') as f:
            users = json.load(f)
            
        if username not in users:
            return False, "Invalid credentials"
            
        user_data = users[username]
        hashed_pw = self.hash_password(password)
        
        if hashed_pw != user_data["password_hash"]:
            return False, "Invalid credentials"
            
        config = self.load_config()
        if config["2fa_enabled"] and user_data.get("2fa_enabled", False):
            code = self.generate_2fa_code()
            self.send_2fa_email(user_data["email"], code)
            return "2fa_required", code
            
        # Generate session key
        self.session_key = Fernet.generate_key()
        self.current_user = username
        return True, "Login successful"
    
    def verify_2fa(self, username, code):
        """Verify 2FA code"""
        # In real system, you would verify against sent code
        # For demo, we'll just accept any 6-digit code
        if len(code) == 6 and code.isdigit():
            self.session_key = Fernet.generate_key()
            self.current_user = username
            return True, "2FA verification successful"
        return False, "Invalid 2FA code"
    
    def validate_username(self, username):
        """Validate username format"""
        return re.match(r'^[a-zA-Z0-9_]{4,20}$', username) is not None
    
    def validate_password(self, password):
        """Validate password meets requirements"""
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[0-9]', password):
            return False
        if not re.search(r'[^A-Za-z0-9]', password):
            return False
        return True
    
    def encrypt_file(self, data):
        """Encrypt file data"""
        fernet = Fernet(self.session_key)
        return fernet.encrypt(data)
    
    def decrypt_file(self, encrypted_data):
        """Decrypt file data"""
        fernet = Fernet(self.session_key)
        return fernet.decrypt(encrypted_data)
    
    def check_buffer_overflow(self, data):
        """Check for potential buffer overflow"""
        return len(data) > BUFFER_OVERFLOW_THRESHOLD
    
    def scan_for_malware(self, data):
        """Basic malware pattern detection"""
        # Very basic pattern matching - in real system use proper antivirus
        malware_patterns = [
            b"malicious", b"virus", b"exploit", 
            b"<?php system(", b"<script>evil", 
            b"DROP TABLE", b"UNION SELECT"
        ]
        
        for pattern in malware_patterns:
            if pattern in data:
                return True
        return False
    
    def create_file(self, filename, data):
        """Create a new secure file"""
        if not self.current_user:
            return False, "Not authenticated"
            
        if len(filename) > MAX_FILENAME_LENGTH:
            return False, "Filename too long"
            
        if self.check_buffer_overflow(data):
            return False, "Potential buffer overflow detected"
            
        if self.scan_for_malware(data):
            return False, "Malware detected in file content"
            
        file_id = str(uuid.uuid4())
        encrypted_data = self.encrypt_file(data)
        
        # Save encrypted file
        with open(f"secure_storage/{file_id}", 'wb') as f:
            f.write(encrypted_data)
            
        # Update file metadata
        with open(FILE_DB, 'r') as f:
            files = json.load(f)
            
        files[file_id] = {
            "filename": filename,
            "owner": self.current_user,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat(),
            "size": len(data),
            "shared_with": [],
            "permissions": {
                "read": True,
                "write": True,
                "share": True
            }
        }
        
        with open(FILE_DB, 'w') as f:
            json.dump(files, f)
            
        # Update user's file list
        with open(USER_DB, 'r') as f:
            users = json.load(f)
            
        users[self.current_user]["files"].append(file_id)
        
        with open(USER_DB, 'w') as f:
            json.dump(users, f)
            
        return True, "File created successfully"
    
    def read_file(self, file_id):
        """Read a secure file"""
        if not self.current_user:
            return False, "Not authenticated"
            
        with open(FILE_DB, 'r') as f:
            files = json.load(f)
            
        if file_id not in files:
            return False, "File not found"
            
        file_info = files[file_id]
        
        # Check permissions
        if (file_info["owner"] != self.current_user and 
            self.current_user not in file_info["shared_with"]):
            return False, "Access denied"
            
        # Read and decrypt file
        try:
            with open(f"secure_storage/{file_id}", 'rb') as f:
                encrypted_data = f.read()
                
            decrypted_data = self.decrypt_file(encrypted_data)
            return True, decrypted_data
        except Exception as e:
            return False, f"Error reading file: {str(e)}"
    
    def update_file(self, file_id, new_data):
        """Update an existing file"""
        if not self.current_user:
            return False, "Not authenticated"
            
        if self.check_buffer_overflow(new_data):
            return False, "Potential buffer overflow detected"
            
        if self.scan_for_malware(new_data):
            return False, "Malware detected in file content"
            
        with open(FILE_DB, 'r') as f:
            files = json.load(f)
            
        if file_id not in files:
            return False, "File not found"
            
        file_info = files[file_id]
        
        # Check permissions
        if (file_info["owner"] != self.current_user or 
            not file_info["permissions"]["write"]):
            return False, "Write permission denied"
            
        # Update file
        encrypted_data = self.encrypt_file(new_data)
        
        try:
            with open(f"secure_storage/{file_id}", 'wb') as f:
                f.write(encrypted_data)
                
            # Update metadata
            file_info["modified"] = datetime.now().isoformat()
            file_info["size"] = len(new_data)
            
            with open(FILE_DB, 'w') as f:
                json.dump(files, f)
                
            return True, "File updated successfully"
        except Exception as e:
            return False, f"Error updating file: {str(e)}"
    
    def share_file(self, file_id, username, permissions):
        """Share a file with another user"""
        if not self.current_user:
            return False, "Not authenticated"
            
        with open(FILE_DB, 'r') as f:
            files = json.load(f)
            
        if file_id not in files:
            return False, "File not found"
            
        file_info = files[file_id]
        
        # Check permissions
        if (file_info["owner"] != self.current_user or 
            not file_info["permissions"]["share"]):
            return False, "Share permission denied"
            
        # Check if target user exists
        with open(USER_DB, 'r') as f:
            users = json.load(f)
            
        if username not in users:
            return False, "Target user not found"
            
        # Update sharing info
        if username not in file_info["shared_with"]:
            file_info["shared_with"].append(username)
            
        # Update permissions
        if permissions:
            file_info["permissions"] = permissions
            
        with open(FILE_DB, 'w') as f:
            json.dump(files, f)
            
        return True, "File shared successfully"
    
    def get_file_metadata(self, file_id):
        """Get metadata for a file"""
        if not self.current_user:
            return False, "Not authenticated"
            
        with open(FILE_DB, 'r') as f:
            files = json.load(f)
            
        if file_id not in files:
            return False, "File not found"
            
        file_info = files[file_id]
        
        # Check permissions
        if (file_info["owner"] != self.current_user and 
            self.current_user not in file_info["shared_with"]):
            return False, "Access denied"
            
        return True, file_info
    
    def list_user_files(self):
        """List all files accessible to current user"""
        if not self.current_user:
            return False, "Not authenticated"
            
        with open(FILE_DB, 'r') as f:
            files = json.load(f)
            
        user_files = []
        
        for file_id, file_info in files.items():
            if (file_info["owner"] == self.current_user or 
                self.current_user in file_info["shared_with"]):
                user_files.append({
                    "id": file_id,
                    "filename": file_info["filename"],
                    "owner": file_info["owner"],
                    "size": file_info["size"],
                    "created": file_info["created"],
                    "modified": file_info["modified"]
                })
                
        return True, user_files
    
    def logout(self):
        """Log out current user"""
        self.current_user = None
        self.session_key = None
        return True, "Logged out successfully"

# Example usage
if __name__ == "__main__":
    fs = SecureFileSystem()
    
    while True:
        print("\nSecure File Management System")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        
        choice = input("Select an option: ")
        
        if choice == "1":
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            email = input("Email (optional): ") or None
            success, message = fs.register_user(username, password, email)
            print(message)
            
        elif choice == "2":
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            status, message = fs.login(username, password)
            
            if status == "2fa_required":
                print("2FA code sent to your email")
                code = input("Enter 2FA code: ")
                success, msg = fs.verify_2fa(username, code)
                print(msg)
                if not success:
                    continue
            else:
                print(message)
                if not status:
                    continue
                    
            # User is now logged in
            while True:
                print("\nFile Operations")
                print("1. Create file")
                print("2. Read file")
                print("3. Update file")
                print("4. Share file")
                print("5. List files")
                print("6. View file metadata")
                print("7. Logout")
                
                op_choice = input("Select an operation: ")
                
                if op_choice == "1":
                    filename = input("Filename: ")
                    data = input("File content: ").encode()
                    success, msg = fs.create_file(filename, data)
                    print(msg)
                    
                elif op_choice == "2":
                    files = fs.list_user_files()
                    if files[0]:
                        for file in files[1]:
                            print(f"ID: {file['id']}, Name: {file['filename']}")
                        file_id = input("Enter file ID to read: ")
                        success, content = fs.read_file(file_id)
                        if success:
                            print("\nFile content:")
                            print(content.decode())
                        else:
                            print(content)
                    else:
                        print(files[1])
                        
                elif op_choice == "3":
                    files = fs.list_user_files()
                    if files[0]:
                        for file in files[1]:
                            print(f"ID: {file['id']}, Name: {file['filename']}")
                        file_id = input("Enter file ID to update: ")
                        new_data = input("New content: ").encode()
                        success, msg = fs.update_file(file_id, new_data)
                        print(msg)
                    else:
                        print(files[1])
                        
                elif op_choice == "4":
                    files = fs.list_user_files()
                    if files[0]:
                        for file in files[1]:
                            print(f"ID: {file['id']}, Name: {file['filename']}")
                        file_id = input("Enter file ID to share: ")
                        username = input("Username to share with: ")
                        print("Set permissions (leave blank for default):")
                        read = input("Allow read? (y/n): ").lower() == 'y'
                        write = input("Allow write? (y/n): ").lower() == 'y'
                        share = input("Allow share? (y/n): ").lower() == 'y'
                        permissions = {
                            "read": read,
                            "write": write,
                            "share": share
                        }
                        success, msg = fs.share_file(file_id, username, permissions)
                        print(msg)
                    else:
                        print(files[1])
                        
                elif op_choice == "5":
                    success, files = fs.list_user_files()
                    if success:
                        print("\nYour files:")
                        for file in files:
                            print(f"ID: {file['id']}")
                            print(f"Name: {file['filename']}")
                            print(f"Size: {file['size']} bytes")
                            print(f"Created: {file['created']}")
                            print(f"Modified: {file['modified']}")
                            print("---")
                    else:
                        print(files)
                        
                elif op_choice == "6":
                    files = fs.list_user_files()
                    if files[0]:
                        for file in files[1]:
                            print(f"ID: {file['id']}, Name: {file['filename']}")
                        file_id = input("Enter file ID to view metadata: ")
                        success, metadata = fs.get_file_metadata(file_id)
                        if success:
                            print("\nFile metadata:")
                            for key, value in metadata.items():
                                print(f"{key}: {value}")
                        else:
                            print(metadata)
                    else:
                        print(files[1])
                        
                elif op_choice == "7":
                    fs.logout()
                    print("Logged out")
                    break
                    
                else:
                    print("Invalid choice")
                    
        elif choice == "3":
            print("Exiting...")
            break
            
        else:
            print("Invalid choice")
