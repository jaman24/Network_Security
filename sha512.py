import hmac
import hashlib

def generate_hmac_sha512(key, message):
 
    # Create a new HMAC object using the provided key and the SHA-512 algorithm
    hmac_obj = hmac.new(key, message.encode('utf-8'), hashlib.sha512)
    
    # Return the HMAC as a hexadecimal string
    return hmac_obj.hexdigest()


def verify_hmac_sha512(key, message, received_hmac):
 
    # Generate a new HMAC for the message and key
    expected_hmac = generate_hmac_sha512(key, message)

    # Use a time-safe comparison to avoid timing attacks
    return hmac.compare_digest(expected_hmac, received_hmac)


if __name__ == "__main__":

    # Secret key (in bytes)
    key = b'supersecretkey'
    print(f"The key: {key}")

    # Message to be authenticated
    message = "This is a secured message with SHA-512."
    print("The Message:", message)

    # Step 1: Sender generates an HMAC using SHA-512
    generated_hmac = generate_hmac_sha512(key, message)
    print("Generated HMAC (SHA-512):", generated_hmac)

    # Step 2: Receiver verifies the message by recomputing the HMAC and comparing
    is_valid = verify_hmac_sha512(key, message, generated_hmac)
    print("Is the message authentic and intact?", is_valid)
