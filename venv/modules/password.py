# ==========================================
# 1. IMPORTS & DEPENDENCIES
# ==========================================
from zxcvbn import zxcvbn # A realistic password strength estimator that checks against known patterns and dictionaries
from getpass import getpass # A module to securely prompt for passwords in the terminal (hides your keystrokes)
import bcrypt # A modern, secure password hashing library that automatically generates and handles "salting"

# ==========================================
# 2. PASSWORD STRENGTH CHECKER FUNCTION
# ==========================================
# Fixed typo: changed checl_strength to check_strength
def check_strength(password):
  """
  Evaluates a password using zxcvbn and returns a formatted feedback string.
  """
  # zxcvbn() returns a dictionary containing a score (0 to 4), warnings, and suggestions
  result = zxcvbn(password)
  score = result["score"] # Extract the numerical score (0 = terrible, 4 = excellent)
  
  # If the score is 3 (Strong)
  if score == 3:
    response = "Strong enough password: Score of 3"
    
  # If the score is 4 (Very Strong)
  elif score == 4:
    response = "Very strong password: Score of 4"
    
  # If the score is 0, 1, or 2 (Weak)
  else:
    # Extract the feedback section from the zxcvbn result
    feedback = result.get("feedback")
    # Extract specific warnings (e.g., "This is a top-10 common password")
    warning = feedback.get("warning")
    # Extract suggestions (e.g., "Add another word or uncommon characters")
    suggestions = feedback.get("suggestions")
    
    # Build the response string indicating weakness
    response = "Weak password: Score of " + str(score)
    # Append the specific warning
    response += "\nWarning: " + warning
    # Loop through and append any helpful suggestions to improve the password
    response += "\nSuggestions: "
    for suggestion in suggestions:
      response += " " + suggestion
      
  # Return the final compiled feedback string
  return response

# ==========================================
# 3. PASSWORD HASHING FUNCTION (BCRYPT)
# ==========================================
def hash_pw(password):
  """
  Hashes a plaintext password securely using bcrypt and a random salt.
  """
  # Generate a random cryptographic "salt". 
  # A salt is random data added to the password before hashing so that identical passwords don't yield identical hashes.
  salt = bcrypt.gensalt()
  
  # Hash the password. bcrypt requires the password to be converted into raw bytes first (.encode()).
  hashed = bcrypt.hashpw(password.encode(), salt)
  
  # Return the hashed byte string (which actually contains the algorithm, cost factor, salt, and the hash itself)
  return hashed

# ==========================================
# 4. PASSWORD VERIFICATION FUNCTION
# ==========================================
def verify_password(pw_attempt, hashed):
  """
  Checks if a plaintext password attempt matches the stored bcrypt hash.
  """
  # bcrypt.checkpw() takes the plain text attempt (encoded to bytes) and the stored hash.
  # It extracts the salt from the stored hash, hashes the attempt with that salt, and compares the results.
  if bcrypt.checkpw(pw_attempt.encode(), hashed):
    return "Password is correct. Access granted!"
  else:
    return "Incorrect password. Access denied"

# ==========================================
# 5. MAIN INTERACTIVE EXECUTION BLOCK
# ==========================================
if __name__ == "__main__":
  
  # Loop continuously until the user provides a password strong enough to pass
  while True:
    # Prompt the user securely (keystrokes will be invisible in the terminal)
    password1 = getpass("Enter a password to check strength: ")
    # OUTPUT BEHAVIOR: The terminal pauses and shows "Enter a password to check strength: "
    
    # Print the evaluation of the entered password
    print(check_strength(password1))
    
    # Check if the evaluation started with "Weak"
    if check_strength(password1).startswith("Weak"):
      # OUTPUT CHANGE: If weak, it prints the warnings/suggestions and asks for a stronger one, repeating the loop.
      print("Please choose a stronger password.")
    else:
      # If the password is a score of 3 or 4, break out of the infinite loop
      break

  # Once a strong password is provided, proceed to hash it
  hashed_password = hash_pw(password1)
  
  # Print out the resulting bcrypt hash
  print("Hashed password: ", hashed_password)
  # OUTPUT CHANGE: Prints a long byte string. Example:
  # b'$2b$12$NqL.7d/hC.X... (long sequence of random characters)'
  # Note: Even if you use the same password multiple times, this output will be completely different every time because of the random salt!

  # Prompt the user to re-enter their password to test the verification function
  attempt = getpass("Re-enter the password to verify: ")
  
  # Check if the re-entered password matches the original hash
  print(verify_password(attempt, hashed_password))
  # OUTPUT CHANGE:
  # If you typed it correctly: "Password is correct. Access granted!"
  # If you made a typo: "Incorrect password. Access denied"