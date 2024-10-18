# Caesar Cipher Encryption Tool

def encrypt(plaintext, key):
    """Encrypts plaintext using Caesar Cipher with the provided key."""
    ciphertext = ""
    
    for char in plaintext:
        if char.isalpha():
            shift = key % 26 
            if char.islower():
                ciphertext += chr((ord(char) - 97 + shift) % 26 + 97)
            elif char.isupper():
                ciphertext += chr((ord(char) - 65 + shift) % 26 + 65)
        else:
            ciphertext += char
    
    return ciphertext


def decrypt(ciphertext, key):
    """Decrypts ciphertext using Caesar Cipher with the provided key."""
    return encrypt(ciphertext, -key)
if __name__ == "__main__":
    action = input("Type 'encrypt' to encrypt a message or 'decrypt' to decrypt: ").lower()
    message = input("Enter your message: ")
    key = int(input("Enter the key (an integer): "))
    
    if action == 'encrypt':
        encrypted_message = encrypt(message, key)
        print(f"Encrypted Message: {encrypted_message}")
    elif action == 'decrypt':
        decrypted_message = decrypt(message, key)
        print(f"Decrypted Message: {decrypted_message}")
    else:
        print("Invalid action. Please choose 'encrypt' or 'decrypt'.")