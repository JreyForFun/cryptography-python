import hashlib

# ==========================================
# 1. BASIC STRING HASHING EXAMPLE (Commented)
# ==========================================
# text = "Hello World!"
# hash_object = hashlib.sha256(text.encode())
# hash_digest = hash_object.hexdigest()
# print("SHA hash of", text, 'is', hash_digest)
# 
# OUTPUT CHANGE / BEHAVIOR:
# If uncommented, this would convert the string "Hello World!" into bytes,
# pass it through the SHA-256 algorithm, and output a 64-character hex string like:
# "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"

# ==========================================
# 2. FILE HASHING FUNCTION
# ==========================================
def hash_file(file_path):
  """
  Reads a file in chunks and returns its unique SHA-256 cryptographic signature.
  """
  # Initialize a new SHA-256 hashing object from the hashlib library
  h = hashlib.new("sha256")
  
  # Safely open the target file in binary read mode ('rb')
  with open(file_path, "rb") as file:
    # Continuously loop to read the file piece by piece (prevents high RAM usage on large files)
    while True:
      # Read a small chunk of data (1,024 bytes / 1 KB at a time)
      chunk = file.read(1024)
      
      # Check if we have reached the end of the file (returns an empty byte string)
      if chunk == b"":
        break # Exit the loop when EOF is reached
        
      # Feed the current chunk into the hashing algorithm to update its state
      h.update(chunk)
      
  # Finalize the cryptographic hashing process and return the 64-character hex digest string
  return h.hexdigest()

# ==========================================
# 3. FILE INTEGRITY VERIFICATION FUNCTION
# ==========================================
def verify_integrity(file1, file2):
  """
  Compares the hashes of two files to verify if their contents match.
  """
  # Generate the SHA-256 hash string for the first file
  hash1 = hash_file(file1)
  
  # Generate the SHA-256 hash string for the second file
  hash2 = hash_file(file2)
  
  # Print out the current files being evaluated for visibility
  print("\nChecking integrity between ", file1, " and ", file2)
  
  # Check if both cryptographic signatures are identical down to the byte level
  if hash1 == hash2:
    # OUTPUT CHANGE: If contents are identical, returns this success message
    return "File is intact. No modifications have been made."
    
  # OUTPUT CHANGE: If any byte differs between the files, hashes won't match, returning a warning
  return "File has been modified. Possibly unsafe."

# ==========================================
# 4. MAIN EXECUTION BLOCK
# ==========================================
if __name__ == "__main__":
  
  # --- Part A: Single File Hash ---
  # Computes and prints the hash for a sample text document
  print("SHA Hash of file is: ", hash_file(r"venv/sample_files/sample.txt"))
  # OUTPUT CHANGE: Displays the computed 64-character hash string of sample.txt
  # e.g., "SHA Hash of file is: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" (if empty)
  
  # --- Part B: Integrity Check 1 (Different PNGs) ---
  # Compare 'asdasda.png' against 'microsoft-logo-png-2420.png'
  # (Using raw strings 'r"..."' to safely handle Windows file path backslashes)
  print(verify_integrity(r"venv\sample_files\asdasda.png", r"venv\sample_files\microsoft-logo-png-2420.png"))
  # OUTPUT CHANGE: 
  # Prints: "Checking integrity between venv\sample_files\asdasda.png and venv\sample_files\microsoft-logo-png-2420.png"
  # Followed by: "File has been modified. Possibly unsafe." (Because the image contents are different)

  # --- Part C: Integrity Check 2 (Another Comparison) ---
  # Compare 'asdasda.png' against 'Beyond Boundaries Background.png'
  print(verify_integrity(r"venv\sample_files\asdasda.png", r"venv\sample_files\Beyond Boundaries Background.png"))
  # OUTPUT CHANGE: 
  # Prints: "Checking integrity between venv\sample_files\asdasda.png and venv\sample_files\Beyond Boundaries Background.png"
  # Followed by: "File has been modified. Possibly unsafe." (Unless by rare coincidence the image contents match)