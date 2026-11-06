# ==========================================
# 1. IMPORTS & DEPENDENCIES
# ==========================================
import secrets # Used to generate cryptographically strong random numbers (for keys and nonces)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM # Symmetric encryption algorithm (Advanced Encryption Standard with Galois/Counter Mode)
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # Asymmetric encryption (RSA) and padding schemes
from cryptography.hazmat.primitives import hashes # Hashing algorithms (like SHA-256) used in RSA padding

# ==========================================
# 2. SYMMETRIC ENCRYPTION (AES-GCM)
# ==========================================
# Symmetric encryption uses the SAME key to encrypt and decrypt the data.
def aes_ed(message):
  """
  Encrypts and then immediately decrypts a message using AES-GCM.
  """
  # Generate a random 32-byte (256-bit) secret key for AES-256
  key = secrets.token_bytes(32)
  
  # Generate a random 12-byte "nonce" (Number Used Once). 
  # This ensures that even if you encrypt the same message twice, the ciphertext will be different.
  nonce = secrets.token_bytes(12)
  
  # Initialize the AES-GCM cipher with our generated secret key
  aes = AESGCM(key)

  # ENCRYPTION:
  # message.encode() converts the string into raw bytes.
  # aes.encrypt() takes the nonce, the byte message, and optional associated data (None here).
  # We prepend (add to the front) the 12-byte nonce to the resulting ciphertext so the decryptor has it.
  ciphertext = nonce + aes.encrypt(nonce, message.encode(), None)
  
  # DECRYPTION:
  # ciphertext[:12] extracts the first 12 bytes (the nonce) we prepended earlier.
  # ciphertext[12:] extracts the rest of the bytes (the actual encrypted message + authentication tag).
  plaintext = aes.decrypt(ciphertext[:12], ciphertext[12:], None)
  
  # Return the key (as hex), the full ciphertext (as hex), and the decrypted message (decoded back to a string)
  return key.hex(), ciphertext.hex(), plaintext.decode()

# ==========================================
# 3. ASYMMETRIC ENCRYPTION (RSA)
# ==========================================
# Asymmetric encryption uses a PAIR of keys: a Public Key (to encrypt) and a Private Key (to decrypt).
def rsa_ed(message):
  """
  Encrypts and then immediately decrypts a message using RSA.
  """
  # Generate a new RSA private key (2048-bit size is standard for security).
  # public_exponent=65537 is the standard mathematical constant used in RSA.
  private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  
  # Derive the public key from the generated private key.
  # The public key can be shared with anyone to let them send you secure messages.
  public_key = private_key.public_key() 

  # ENCRYPTION:
  # We use the PUBLIC key to encrypt the message.
  ciphertext = public_key.encrypt(
    message.encode(), # Convert string to bytes
    # Padding adds random data to the message before encrypting to prevent pattern-guessing attacks.
    # OAEP (Optimal Asymmetric Encryption Padding) with SHA-256 is the modern, highly secure standard.
    padding.OAEP(
      mgf = padding.MGF1(algorithm=hashes.SHA256()),
      algorithm=hashes.SHA256(),
      label=None
    )
  )
  
  # DECRYPTION:
  # We use the PRIVATE key to decrypt the message back to its original state.
  # The padding settings must match exactly what was used during encryption.
  plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
      mgf = padding.MGF1(algorithm=hashes.SHA256()),
      algorithm=hashes.SHA256(),
      label=None
    )
  )
  
  # Return the ciphertext (as hex) and the decrypted message (decoded back to a string)
  return ciphertext.hex(), plaintext.decode()

# ==========================================
# 4. MAIN EXECUTION BLOCK
# ==========================================
if __name__ == "__main__":
  
  # --- Part A: Execute Symmetric (AES) Encryption ---
  print(aes_ed("Hello, AES!"))
  # OUTPUT CHANGE / BEHAVIOR:
  # Because the key and nonce are randomly generated every time the script runs, 
  # the first two elements (key and ciphertext) will be DIFFERENT on every single execution!
  # Example output format:
  # ('a1b2c3d4e5f6... (64 hex chars for 32-byte key)', 
  #  '1a2b3c... (hex string of 12-byte nonce + encrypted message + auth tag)', 
  #  'Hello, AES!') # The plaintext will always successfully match the input.

  # --- Part B: Execute Asymmetric (RSA) Encryption ---
  print(rsa_ed("Hello, RSA!"))
  # OUTPUT CHANGE / BEHAVIOR:
  # Because a brand new 2048-bit RSA key pair is generated every time, AND OAEP padding 
  # adds its own randomness, the ciphertext will be completely DIFFERENT on every run.
  # Example output format:
  # ('f8e7d6c5b4a3... (512 hex chars representing the large 2048-bit encrypted block)', 
  #  'Hello, RSA!') # The plaintext will always successfully match the input.