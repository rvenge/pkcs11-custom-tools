"""
Sample program to modify the CKA_LABEL of a key 
Uses python-pkcs11 as the wrapper

Requirements:
    pip install python-pkcs11
"""

import pkcs11
from pkcs11 import ObjectClass, Attribute
import sys

# Configuration
PKCS11_LIB_PATH = 'C:\\Program Files\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast.dll'
TOKEN_LABEL = 'loadshared accelerator'
USER_PIN = '1234'  # Update with your actual PIN

# Initialize library and token
try:
    lib = pkcs11.lib(PKCS11_LIB_PATH)
    token = lib.get_token(token_label=TOKEN_LABEL)
    print(f"Connected to HSM token: {TOKEN_LABEL}")
except Exception as e:
    print(f"Error connecting to HSM: {e}")
    sys.exit(1)

def modify_key_label(current_label, new_label, object_class):
    """
    Modify a key's label
    
    Args:
        current_label: Current key label
        new_label: New key label to set
        object_class: ObjectClass.PRIVATE_KEY or ObjectClass.PUBLIC_KEY
    
    Returns:
        bool: True if successful, False otherwise
    """
    key_type = "Private" if object_class == ObjectClass.PRIVATE_KEY else "Public"
    
    try:
        with token.open(user_pin=USER_PIN, rw=True) as session:
            # Find the key object to modify
            key = session.get_key(label=current_label, object_class=object_class)
            
            # Modify the key's label using proper attribute assignment
            key[Attribute.LABEL] = new_label
            
            print(f"{key_type} key label changed successfully: '{current_label}' -> '{new_label}'")
            return True
            
    except pkcs11.exceptions.NoSuchKey:
        print(f"Error: {key_type} key not found with label '{current_label}'")
        return False
    except pkcs11.exceptions.TokenNotPresent:
        print(f"Error: Token not present: {TOKEN_LABEL}")
        return False
    except pkcs11.exceptions.PinIncorrect:
        print(f"Error: Incorrect PIN for token")
        return False
    except Exception as e:
        print(f"Error modifying {key_type.lower()} key '{current_label}': {e}")
        return False


def main():
    """Main function for key label modification"""
    
    # Define the key operations to perform
    # Format: (current_label, new_label, object_class)
    key_operations = [
        ('priv-rsa_key', 'priv-rsa_key_new', ObjectClass.PRIVATE_KEY), # Modify private key label
        ('pub-rsa_key', 'pub-rsa_key_new', ObjectClass.PUBLIC_KEY), # Modify public key label
    ]
    
    print("Starting key label modification...")
    success_count = 0
    
    for current_label, new_label, object_class in key_operations:
        if modify_key_label(current_label, new_label, object_class):
            success_count += 1
    
    print(f"\nCompleted: {success_count}/{len(key_operations)} operations successful")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
