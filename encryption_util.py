from cryptography.fernet import Fernet

def load_key():
    return open("secret.key", "rb").read()

def encrypt_password(password):
    key = load_key()
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    try:
        key = load_key()
        f = Fernet(key)
        return f.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        # Handle decryption errors gracefully
        print(f"Decryption error: {e}")
        return "🔒 Error: Could not decrypt"
