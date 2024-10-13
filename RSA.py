from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# Generate RSA key pair (public and private keys)
keyPair = RSA.generate(1024)

# Get the public key
publicKey = keyPair.publickey()

# Display public key
print(f"Public key: (n={hex(publicKey.n)}, e={hex(publicKey.e)})")
pubKeyPEM = publicKey.exportKey()
print(pubKeyPEM.decode('ascii'))

# Display private key
print(f"Private key: (n={hex(keyPair.n)}, d={keyPair.d})")
privateKeyPEM = keyPair.exportKey()
print(privateKeyPEM.decode('ascii'))

# Example message
msg = 'iam a student'

# Convert the string message to bytes
msg_bytes = msg.encode('utf-8')  # Convert string to bytes

# Encrypt the message using the public key
encryptor = PKCS1_OAEP.new(publicKey)
encrypted = encryptor.encrypt(msg_bytes)

# Print the encrypted message in hex format
print("Encrypted:", binascii.hexlify(encrypted))
