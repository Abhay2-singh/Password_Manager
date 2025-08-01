from encryption_util import encrypt_password, decrypt_password

# Test password
password = "hello123"

# Encrypt
encrypted = encrypt_password(password)
print("Encrypted:", encrypted)

# Decrypt
decrypted = decrypt_password(encrypted)
print("Decrypted:", decrypted)
