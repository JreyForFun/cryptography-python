# ==========================================
# 1. IMPORTS
# ==========================================
# Import functions from your custom modules (hash.py, encryption.py, password.py)
from modules.hash import hash_file, verify_integrity
from modules.encryption import aes_ed, rsa_ed
from modules.password import check_strength, hash_pw, verify_password

# Import getpass to securely hide password typing in the terminal
from getpass import getpass

# ==========================================
# 2. MENU DISPLAY FUNCTION
# ==========================================
def menu():
  """
  Prints the available operations for the user to choose from.
  """
  print("\nSelect operation:")
  print("1. Hash file")
  print("2. Check file integrity")
  print("3. AES Encryption/Decrypt")
  print("4. RSA Encrypt/Decrypt") # Fixed typo: changed "4," to "4."
  print("5. Password Manager")
  print("0. Exit")

  # Print a stylized initialization message
  print("""
    Init Crypt Toolkit v1.0...
  """)

# ==========================================
# 3. MAIN INTERACTIVE LOOP
# ==========================================
# Run an infinite loop to keep the program alive until the user chooses to exit
while True:
  # Display the menu options
  menu()
  
  # Prompt the user for their choice. input() always returns a string.
  choice = input("Enter choice(0-5): ")
  
  # --- CHOICE 0: EXIT ---
  if choice == "0":
    # Break completely out of the 'while True' loop, moving to the end of the script
    break

  # --- CHOICE 1: HASH A FILE ---
  elif choice == "1":
    # Ask the user for a file path (e.g., venv/sample_files/sample.txt)
    file_path = input("enter file path: ")
    # Call hash_file() from your hash module and print the 64-character SHA-256 result
    print("\nSHA Hash of File is: ", hash_file(file_path))
    # OUTPUT BEHAVIOR: Prints the hex hash of the target file.

  # --- CHOICE 2: VERIFY FILE INTEGRITY ---
  elif choice == "2":
    # Ask the user for the paths of the two files they want to compare
    file_path1 = input("enter file path 1: ")
    file_path2 = input("enter file path 2: ")
    # Call verify_integrity() to check if the files match exactly
    print(verify_integrity(file_path1, file_path2))
    # OUTPUT BEHAVIOR: Prints "File is intact..." or "File has been modified..."

  # --- CHOICE 3: SYMMETRIC (AES) ENCRYPTION ---
  elif choice == "3":
    # Prompt for a message, but note that the .encode() here converts the string input into bytes.
    # (If your aes_ed function in encryption.py also does .encode(), you might need to remove one of them!)
    message = input("Enter message: ") # Removed .encode() assuming your aes_ed handles string inputs
    
    # Unpack the three returned values from your aes_ed function
    key, ciphertext, plaintext = aes_ed(message)
    
    # Print the randomly generated AES key, the encrypted data, and the decrypted result
    print("AES Key: ", key)
    print("AES Ciphertext: ", ciphertext)
    print("AES Plaintext: ", plaintext)
    # OUTPUT BEHAVIOR: Displays long hexadecimal strings for the key and ciphertext, and the original message for plaintext.

  # --- CHOICE 4: ASYMMETRIC (RSA) ENCRYPTION ---
  elif choice == "4":
    # Prompt for a message to encrypt with RSA
    message = input("Enter message: ")
    
    # Unpack the two returned values from your rsa_ed function
    ciphertext, plaintext = rsa_ed(message)
    
    # Print the RSA encrypted block and the decrypted result
    print("RSA Message, encrypted with a public key:", ciphertext)
    print("RSA Message, encrypted with a private key:", plaintext)

  # --- CHOICE 5: PASSWORD MANAGER ---
  elif choice == "5":
    # Start a nested loop specifically to force the user to pick a strong password
    while True:
      # Securely ask for a password without showing keystrokes
      password1 = getpass("Enter a password to check strength: ")
      
      # Print the evaluation (Score, Warnings, Suggestions)
      print(check_strength(password1))
      
      # NOTE: Fixed 'password' to 'password1' and 'startswoth' to 'startswith'
      if check_strength(password1).startswith("Weak"):
        # If it starts with "Weak", the loop repeats, asking them again
        print("Please choose a stronger password.")
      else:
        # If it's a score of 3 or 4, break out of this nested password loop
        break
        
    # Hash the strong password using bcrypt
    hashed_password = hash_pw(password1)
    print("Hashed password: ", hashed_password)
    
    # Verify the password by having them type it again
    attempt = getpass("Re-enter the password to verify: ")
    print(verify_password(attempt, hashed_password))
    # OUTPUT BEHAVIOR: Validates the re-entered password against the bcrypt hash and prints Success/Denied.

  # --- INVALID CHOICE CATCH-ALL ---
  else:
    # If the user types anything other than 0, 1, 2, 3, 4, or 5
    print("Invalid choice.")
    # The loop will then automatically restart and show the menu again

# ==========================================
# 4. EXIT SCRIPT
# ==========================================
# This only runs after the user selects "0" to break the main while loop
print("Agent you are exiting the Crpt Toolkit. Stay sharp and secure out there!")