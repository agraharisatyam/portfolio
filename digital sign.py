from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


# Step 1: Generate RSA Keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Step 2: Sign the message
def sign_message(private_key, message):
    # Hash the message
    message = message.encode()  # Encoding the message to bytes
    hash_algorithm = hashes.SHA256()
    
    # Create the signature
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), 
        hash_algorithm
    )
    return signature

# Step 3: Verify the signature
def verify_signature(public_key, message, signature):
    message = message.encode()  # Encoding the message to bytes
    hash_algorithm = hashes.SHA256()
    
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hash_algorithm
        )
        print("Signature is valid.")
    except Exception as e:
        print("Signature is invalid. Error:", e)


# Example usage
if __name__ == "__main__":
    # Generate keys
    private_key, public_key = generate_keys()
    
    # Message to be signed
    message = "This is a message to be signed."

    # Sign the message
    signature = sign_message(private_key, message)
    print("Signature created.")

    # Verify the signature
    verify_signature(public_key, message, signature)
