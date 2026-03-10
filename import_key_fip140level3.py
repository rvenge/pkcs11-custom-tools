# Uses nCipher HSM to generate an AES wrapping key, then wraps and unwraps
# external OpenSSL-generated keys onto the HSM via PKCS#11.
# Uses wrap/unwrap (not encrypt/decrypt) to meet FIPS 140 Level 3 import requirements.
#
# Ref: https://python-pkcs11.readthedocs.io/en/latest/applied.html#wrapping-unwrapping
# Ref: https://python-pkcs11.readthedocs.io/en/latest/applied.html#importing-exporting-keys

import pkcs11
import ctypes
import struct
import pandas as pd
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.util.rsa import decode_rsa_public_key, decode_rsa_private_key
from asn1crypto import pem
from asn1crypto.keys import PublicKeyInfo, PrivateKeyInfo

# Define DLL path and initialize PKCS#11 library
# Note: The path to the DLL may vary based on your installation and operating system.
LIB = 'C:\\Program Files\\nCipher\\nfast\\toolkits\\pkcs11\\cknfast.dll'

# Initialize the PKCS#11 library
lib = pkcs11.lib(LIB)

# Define slot/token credentials

# Slot 0 with CKNFAST_LOADSHARING=1 in cknfastrc file
# Use cklist or ckcheckinst from /opt/nfast/bin/ or %NFAST_HOME%\bin to determine your available PCKS#11 slots & labels. 
token = lib.get_token(token_label='loadshared accelerator')


# Open a read/write session (required for creating persistent objects)

# Slot 0 takes any pin, change to correct pin ,or use getpass to parse the pin securely if using OCS/Softcard.
# Ensure to preload the OCS/Softcard before program execution. 
with token.open(rw=True, user_pin='1234') as session: 

    # 1: Generate AES wrapping key on the HSM --
    wrapping_key = session.generate_key(KeyType.AES, 256, store=True, template={
        Attribute.WRAP: True,
        Attribute.UNWRAP: True,
        Attribute.EXTRACTABLE: False,
        Attribute.SENSITIVE: True,
        Attribute.LABEL: 'aes_wrapping_key',
    })
    print("Generating AES-256 wrapping key on HSM...                 done.")

    # File paths for OpenSSL-generated keys // NOTE: Update these paths to point to your actual key files
    pub_key_path  = 'C:\\Users\\admin\\Desktop\\rsa_keypair_pub.pem'
    priv_key_path = 'C:\\Users\\admin\\Desktop\\rsa_keypair.pem'

    print(f"Loading RSA key pair from disk...                         done.")

    
    # 3: Import the RSA public key (direct - not sensitive) --
    with open(pub_key_path, 'rb') as f:
        pub_pem = f.read()

    # PEM to DER conversion  (ref: asn1crypto.pem)
    if pem.detect(pub_pem):
        _, _, pub_der = pem.unarmor(pub_pem)
    else:
        pub_der = pub_pem

    # openssl pkey -pubout produces SPKI (SubjectPublicKeyInfo) format.
    # decode_rsa_public_key() expects PKCS#1, so extract the inner key.
    pub_key_info  = PublicKeyInfo.load(pub_der)
    pkcs1_pub_der = pub_key_info['public_key'].parsed.dump()

    pub_attrs = decode_rsa_public_key(pkcs1_pub_der)
    pub_attrs[Attribute.LABEL] = 'rsa__pub_keypair'
    pub_attrs[Attribute.TOKEN] = True
    pub_key = session.create_object(pub_attrs)
    modulus_bits = len(pub_attrs[Attribute.MODULUS]) * 8
    print(f"Importing RSA-{modulus_bits} public key onto HSM...                 done.")

    # 4: Wrap / unwrap the RSA private key --
    with open(priv_key_path, 'rb') as f:
        priv_pem = f.read()

    # PEM to DER conversion  (PKCS#8 from openssl genpkey, or PKCS#1 from openssl genrsa)
    if pem.detect(priv_pem):
        _, _, priv_der = pem.unarmor(priv_pem)
    else:
        priv_der = priv_pem

    # openssl genpkey produces PKCS#8 (PrivateKeyInfo) format.
    # decode_rsa_private_key() expects PKCS#1 (RSAPrivateKey), so extract the inner key.
    priv_key_info  = PrivateKeyInfo.load(priv_der)
    pkcs1_priv_der = priv_key_info['private_key'].parsed.dump()

    # Create a temporary, extractable private key from the PKCS#1 DER data
    priv_attrs = decode_rsa_private_key(pkcs1_priv_der)
    priv_attrs[Attribute.SENSITIVE] = False
    priv_attrs[Attribute.EXTRACTABLE] = True
    temp_priv = session.create_object(priv_attrs)
    priv_modulus_bits = len(priv_attrs[Attribute.MODULUS]) * 8
    print(f"Creating temporary RSA-{priv_modulus_bits} private key for wrapping...   done.")

    # Wrap the temporary private key using AES_CBC_PAD (handles non-block-aligned data)
    iv = session.generate_random(128)  # 128-bit IV for AES
    wrapped_rsa = wrapping_key.wrap_key(
        temp_priv,
        mechanism=Mechanism.AES_CBC_PAD,
        mechanism_param=iv,
    )
    temp_priv.destroy()
    print(f"Wrapping private key with AES-256 (CKM_AES_CBC_PAD)...    done. ({len(wrapped_rsa)} bytes)")

    # Unwrap to create a permanent, protected private key on the HSM.
    #
    # NOTE: python-pkcs11's unwrap_key() has a bug where it adds CKA_ENCRYPT,
    # CKA_WRAP, and CKA_VERIFY to the template for ALL key types. nCipher HSMs
    # reject those attributes for CKO_PRIVATE_KEY. As a workaround, we call
    # C_UnwrapKey directly via ctypes with a clean template.

    # -- ctypes C_UnwrapKey call --
    # PKCS#11 uses pack=1 on Windows (per pkcs11t.h)
    class CK_MECHANISM(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("mechanism",      ctypes.c_ulong),
            ("pParameter",     ctypes.c_void_p),
            ("ulParameterLen", ctypes.c_ulong),
        ]

    class CK_ATTRIBUTE(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("type",       ctypes.c_ulong),
            ("pValue",     ctypes.c_void_p),
            ("ulValueLen", ctypes.c_ulong),
        ]

    # PKCS#11 constants
    CKM_AES_CBC_PAD = 0x1085
    CKA_CLASS       = 0x0000;  CKO_PRIVATE_KEY = 3
    CKA_KEY_TYPE    = 0x0100;  CKK_RSA         = 0
    CKA_TOKEN       = 0x0001
    CKA_PRIVATE     = 0x0002
    CKA_LABEL       = 0x0003
    CKA_ID          = 0x0102
    CKA_SENSITIVE   = 0x0103
    CKA_DECRYPT     = 0x0105
    CKA_UNWRAP      = 0x0107
    CKA_SIGN        = 0x0108
    CKA_DERIVE      = 0x010C
    CKA_EXTRACTABLE = 0x0162

    # Helpers to create ctypes buffers for attribute values
    _bufs = []  # prevent garbage collection

    def _ulong_val(v):
        b = struct.pack('<L', v)
        buf = ctypes.create_string_buffer(b)
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p), len(b)

    def _bool_val(v):
        b = struct.pack('B', 1 if v else 0)
        buf = ctypes.create_string_buffer(b)
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p), 1

    def _str_val(v):
        enc = v.encode('utf-8')
        buf = ctypes.create_string_buffer(enc, len(enc))
        _bufs.append(buf)
        return ctypes.cast(buf, ctypes.c_void_p), len(enc)

    # Template: ONLY attributes valid for CKO_PRIVATE_KEY
    # (no CKA_ENCRYPT, CKA_WRAP, CKA_VERIFY)
    attr_defs = [
        (CKA_CLASS,       _ulong_val(CKO_PRIVATE_KEY)),
        (CKA_KEY_TYPE,    _ulong_val(CKK_RSA)),
        (CKA_TOKEN,       _bool_val(True)),
        (CKA_PRIVATE,     _bool_val(True)),
        (CKA_LABEL,       _str_val('rsa_priv_keypair')),
        (CKA_ID,          (ctypes.c_void_p(0), 0)),  # empty
        (CKA_SENSITIVE,   _bool_val(True)),
        (CKA_EXTRACTABLE, _bool_val(False)),
        (CKA_DECRYPT,     _bool_val(True)),
        (CKA_SIGN,        _bool_val(True)),
        (CKA_UNWRAP,      _bool_val(True)),
        (CKA_DERIVE,      _bool_val(False)),
    ]

    n = len(attr_defs)
    tmpl = (CK_ATTRIBUTE * n)()
    for i, (atype, (ptr, size)) in enumerate(attr_defs):
        tmpl[i].type       = atype
        tmpl[i].pValue     = ptr
        tmpl[i].ulValueLen = size

    # Setup mechanism (AES_CBC_PAD with IV)
    iv_arr = (ctypes.c_ubyte * len(iv))(*iv)
    mech = CK_MECHANISM()
    mech.mechanism      = CKM_AES_CBC_PAD
    mech.pParameter     = ctypes.cast(iv_arr, ctypes.c_void_p)
    mech.ulParameterLen = len(iv)

    # Wrapped key buffer
    wk = (ctypes.c_ubyte * len(wrapped_rsa))(*wrapped_rsa)

    # Output handle
    new_handle = ctypes.c_ulong(0)

    # Load the same DLL via ctypes (shares the in-process PKCS#11 state)
    _dll = ctypes.CDLL(LIB)
    _dll.C_UnwrapKey.argtypes = [
        ctypes.c_ulong,                          # hSession
        ctypes.POINTER(CK_MECHANISM),            # pMechanism
        ctypes.c_ulong,                          # hUnwrappingKey
        ctypes.POINTER(ctypes.c_ubyte),          # pWrappedKey
        ctypes.c_ulong,                          # ulWrappedKeyLen
        ctypes.POINTER(CK_ATTRIBUTE),            # pTemplate
        ctypes.c_ulong,                          # ulAttributeCount
        ctypes.POINTER(ctypes.c_ulong),          # phKey
    ]
    _dll.C_UnwrapKey.restype = ctypes.c_ulong

    rv = _dll.C_UnwrapKey(
        ctypes.c_ulong(session._handle),
        ctypes.byref(mech),
        ctypes.c_ulong(wrapping_key._handle),
        wk,
        ctypes.c_ulong(len(wrapped_rsa)),
        tmpl,
        ctypes.c_ulong(n),
        ctypes.byref(new_handle),
    )

    if rv != 0:
        raise RuntimeError(f"C_UnwrapKey failed: CKR 0x{rv:08X}")

    print(f"Unwrapping private key onto HSM (C_UnwrapKey)...          done. (handle={new_handle.value})")

    # -- Final summary --
    print("")
    summary = pd.DataFrame([
        {
            'Label': 'aes_wrapping_key',
            'Key Type': 'AES-256',
            'Class': 'SECRET_KEY',
            'Token': 'Yes',
            'Method': 'HSM Generated',
            'Sensitive': 'Yes',
            'Extractable': 'No',
        },
        {
            'Label': 'rsa_pub_keypair',
            'Key Type': f'RSA-{modulus_bits}',
            'Class': 'PUBLIC_KEY',
            'Token': 'Yes',
            'Method': 'Direct Import',
            'Sensitive': 'No',
            'Extractable': 'N/A',
        },
        {
            'Label': 'rsa_keypair',
            'Key Type': f'RSA-{priv_modulus_bits}',
            'Class': 'PRIVATE_KEY',
            'Token': 'Yes',
            'Method': 'Wrap/Unwrap',
            'Sensitive': 'Yes',
            'Extractable': 'No',
        },
    ])
    cols = [
        ('Label',       18),
        ('Key Type',    10),
        ('Class',       12),
        ('Token',        6),
        ('Method',      15),
        ('Sensitive',   10),
        ('Extractable', 12),
    ]
    header = '  '.join(name.ljust(w) for name, w in cols)
    sep = '-' * len(header)
    print(sep)
    print('HSM KEY IMPORT SUMMARY'.center(len(header)))
    print(sep)
    print(header)
    print(sep)
    for _, row in summary.iterrows():
        print('  '.join(str(row[name]).ljust(w) for name, w in cols))
    print(sep)
    print('All keys successfully imported onto the HSM via wrap/unwrap.')
