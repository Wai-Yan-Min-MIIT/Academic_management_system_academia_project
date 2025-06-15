from argon2 import PasswordHasher

# Function to create a password hash
def create_password(password):
    ph = PasswordHasher()
    hashed_password = ph.hash(password)
    return hashed_password

# Function to extract salt from the hashed password
def extract_salt(hashed_password):
    parts = hashed_password.split('$')
    salt = parts[4] if len(parts) > 4 else None
    return salt

# Function to verify the password
def verify_password(hashed_password, password):
    ph = PasswordHasher()
    try:
        ph.verify(hashed_password, password)
        return True
    except:
        return False

def main():
    # Create a password
    password = input("Enter a password to hash: ")
    hashed_password = create_password(password)
    salt = extract_salt(hashed_password)
    
    print(f"Created Password Hash: {hashed_password}")
    print(f"Extracted Salt: {salt}")

    # Verify the password
    verify_password_input = input("Re-enter the password to verify: ")
    is_correct = verify_password(hashed_password, verify_password_input)
    
    if is_correct:
        verified_salt = extract_salt(hashed_password)
        print("Password verification successful!")
        print(f"Verified Password Hash: {hashed_password}")
        print(f"Verified Salt: {verified_salt}")
    else:
        print("Password verification failed!")

if __name__ == "__main__":
    main()
