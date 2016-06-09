#! /usr/bin/env python3

"""Cryptographic algorithm comparison by Brendan Sweeney, CSS 527, Assignment 2.

This script uses three cryptographic libraries for Python: cryptography,
PyCrypto, and python-gnupg. Several cryptographic operations are performed from
each library and those operations timed. The results are placed in a list which
is printed to stdout upon completion. Otherwise, operation is completely silent.
The validity of encryption and decryption are not verified, as relative
performance is the primary focus of this script.
"""

import os
from timeit import Timer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import asymmetric, hashes
from Crypto.Hash import RIPEMD, SHA512, MD5
from Crypto.Cipher import DES3, AES, CAST, ARC4
from Crypto.PublicKey import RSA #, ElGamal
from gnupg import GPG

# Number of times to perform each cryptographic operation.
RUN_COUNT = 5
# Asymmetric keys will be 2**KEY_EXP bits in length
KEY_EXP = 12
# To avoid generating a new PGP key in GPG on every run
KEY_ID = 'E5CD897D9D2F8927'
PASSPHRASE = 'oogiblah'
# Number of bytes to encrypt at a time with asymmetric algorithms
BYTE_RANGE = 2**(KEY_EXP - 1) // 8



def pub_key_encrypt(message, public_key, pad):
    """Encrypt data using public-key cryptography in ECB mode.

    Returns a list of public-key-encrypted data segments. Due to padding, this
    structure may be significantly larger than the data that were encrypted.

    Keyword arguments:
    message -- A byte array of data to encrypt.
    public_key -- The asymmetric encryption key that will be used to encrypt the
                  data. This may be the entire key or only the public portion.
    pad -- Padding data for those schemes that require it.
    """
    # List to store each encrypted data segment
    result = []
    # Index into the data byte array
    start = 0
    
    while start < len(message):
        enctext = message[start:start + BYTE_RANGE]
        result.append(public_key.encrypt(enctext, pad))
        start += BYTE_RANGE
    
    return result



def cryptography_pub_key_decrypt(enctext, private_key, pad):
    """Decrypt data that were encrypted using the cryptography library.

    Returns a byte array of deciphered data that is equivalent to the data that
    were passed to the original encryption operation.

    Keyword arguments:
    enctext -- A list of public-key-encrypted data segments.
    private_key -- The asymmetric decryption key that will be used to decrypt
                   the data. This may be the entire key or only the private
                   portion.
    pad -- Padding data that were used to ensure each encrypted element has the
           same bit length as the decryption key.
    """
    result = bytearray()
    
    for message in enctext:
        result.extend(private_key.decrypt(message, pad))
    
    return result



def pycrypto_pub_key_decrypt(enctext, private_key):
    """Decrypt data that were encrypted using the PyCrypto library.

    Returns a byte array of deciphered data that is equivalent to the data that
    were passed to the original encryption operation.

    Keyword arguments:
    enctext -- A list of public-key-encrypted data segments.
    private_key -- The asymmetric decryption key that will be used to decrypt
                   the data. This may be the entire key or only the private
                   portion.
    """
    result = bytearray()
    
    for message in enctext:
        result.extend(private_key.decrypt(message))
    
    return result



if __name__ == "__main__":
    # File is read in and buffered as the message for all algorithms to use
    with open('plain.bin', 'rb') as infile:
        message = infile.read()
    
    # Needed for cryptography library
    backend = default_backend()
    # All symmetric ciphers use the same key and IVs to maintain consistency
    iv8  = os.urandom(8)
    iv16 = os.urandom(16)
    key  = os.urandom(16)
    # A list of lists to be built around the different operations and results
    result = []
    
    
# ********** ############################ **************************************
# ********** BEGIN 'CRYPTOGRAPHY' LIBRARY **************************************
# ********** ############################ **************************************
    
    # List for all operations in a single library, starting with cryptography
    lib_run = ['cryptography']
    
    # BEGIN BLOCK CIPHER OPERATIONS
    # List for all operations in a cipher set, such as block, stream, etc.
    set_run = ['block']
    # Needed for Timeit; all symmetric ciphers can use the same setup
    setup = """\
from __main__ import cipher, message, enctext
encryptor = cipher.encryptor()
decryptor = cipher.decryptor()
"""
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    # List for all operations of a single algorithm
    algo_run = ['TripleDES']
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv8), backend=backend)
    encryptor = cipher.encryptor()
    enctext = encryptor.update(message) + encryptor.finalize()
    # List to mark encryption operations and hold the results
    enc_run = ['encrypt']
    # Command that will be timed for encryption operations; updated frequently
    enc_trial = Timer("encryptor.update(message) + encryptor.finalize()", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    # List to mark decryption operations and hold the results
    dec_run = ['decrypt']
    # Command that will be timed for decryption operations; updated frequently
    dec_trial = Timer("decryptor.update(enctext) + decryptor.finalize()", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['AES']
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv16), backend=backend)
    encryptor = cipher.encryptor()
    enctext = encryptor.update(message) + encryptor.finalize()
    enc_run = ['encrypt']
    enc_trial = Timer("encryptor.update(message) + encryptor.finalize()", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer("decryptor.update(enctext) + decryptor.finalize()", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['CAST5']
    cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv8), backend=backend)
    encryptor = cipher.encryptor()
    enctext = encryptor.update(message) + encryptor.finalize()
    enc_run = ['encrypt']
    enc_trial = Timer("encryptor.update(message) + encryptor.finalize()", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer("decryptor.update(enctext) + decryptor.finalize()", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    lib_run.append(set_run)
    
    
    # BEGIN STREAM CIPHER OPERATIONS
    set_run = ['stream']
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['ARC4']
    cipher = Cipher(algorithms.ARC4(key), mode=None, backend=backend)
    encryptor = cipher.encryptor()
    enctext = encryptor.update(message) + encryptor.finalize()
    enc_run = ['encrypt']
    enc_trial = Timer("encryptor.update(message) + encryptor.finalize()", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer("decryptor.update(enctext) + decryptor.finalize()", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['AES-CFB']
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv16), backend=backend)
    encryptor = cipher.encryptor()
    enctext = encryptor.update(message) + encryptor.finalize()
    enc_run = ['encrypt']
    enc_trial = Timer("encryptor.update(message) + encryptor.finalize()", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer("decryptor.update(enctext) + decryptor.finalize()", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['CAST5-CFB']
    cipher = Cipher(algorithms.CAST5(key), modes.CFB(iv8), backend=backend)
    encryptor = cipher.encryptor()
    enctext = encryptor.update(message) + encryptor.finalize()
    enc_run = ['encrypt']
    enc_trial = Timer("encryptor.update(message) + encryptor.finalize()", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer("decryptor.update(enctext) + decryptor.finalize()", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    lib_run.append(set_run)
    
    
    # BEGIN ASYMMETRIC CIPHER OPERATIONS
    set_run = ['asymmetric']
    
    # cryptography only supports RSA, DSA, and ECDSA asymmetric ciphers; cannot
    # encrypt with DSA or ECDSA
#    algo_run = ['dsa']
#    setup = """\
#from __main__ import private_key, verifier, message
#from cryptography.hazmat.primitives import hashes
#signer = private_key.signer(hashes.SHA256())
#"""
#    private_key = asymmetric.dsa.generate_private_key(key_size=1024,
#                                                      backend=backend)
#    public_key = private_key.public_key()
#    signer = private_key.signer(hashes.SHA512())
#    signer.update(message)
#    signature = signer.finalize()
#    verifier = public_key.verifier(signature, hashes.SHA512())
#    enc_run = ['sign']
#    enc_trial = Timer("signer.update(message); signer.finalize()", setup)
#    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
#    algo_run.append(enc_run)
#    dec_run = ['verify']
#    dec_trial = Timer("verifier.update(message); verifier.verify()", setup)
#    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
#    algo_run.append(dec_run)
#    set_run.append(algo_run)
#    
#    algo_run = ['ecdsa']
#    setup = """\
#from __main__ import private_key, verifier, message
#from cryptography.hazmat.primitives import asymmetric, hashes
#signer = private_key.signer(asymmetric.ec.ECDSA(hashes.SHA512()))
#"""
#    private_key = asymmetric.ec.generate_private_key(asymmetric.ec.SECP521R1(), 
#                                                     backend=backend)
#    public_key = private_key.public_key()
#    signer = private_key.signer(asymmetric.ec.ECDSA(hashes.SHA512()))
#    signer.update(message)
#    signature = signer.finalize()
#    verifier = public_key.verifier(signature,
#                                   asymmetric.ec.ECDSA(hashes.SHA512()))
#    enc_run = ['sign']
#    enc_trial = Timer("signer.update(message); signer.finalize()", setup)
#    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
#    algo_run.append(enc_run)
#    dec_run = ['verify']
#    dec_trial = Timer("verifier.update(message); verifier.verify()", setup)
#    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
#    algo_run.append(dec_run)
#    set_run.append(algo_run)
    
    # Create key pair and reusable padding
    algo_run = ['rsa']
    private_key = asymmetric.rsa.generate_private_key(public_exponent=65537,
                                                      key_size=2**KEY_EXP,
                                                      backend=backend)
    public_key = private_key.public_key()
    pad = asymmetric.padding.OAEP(
                        mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA1()),
                        algorithm=hashes.SHA1(),
                        label=None)
    # Get single encrypted message to use for all decryption operations
    enctext = pub_key_encrypt(message, public_key, pad)
    enc_run = ['encrypt']
    # setup is unique for each asymmetric operation
    setup = """\
from __main__ import pub_key_encrypt, public_key, message, pad
"""
    enc_trial = Timer("pub_key_encrypt(message, public_key, pad)",
                      setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    setup = """\
from __main__ import cryptography_pub_key_decrypt, private_key, enctext, pad
"""
    dec_trial = Timer("cryptography_pub_key_decrypt(enctext, private_key, pad)",
                      setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    lib_run.append(set_run)
    
    
    # BEGIN HASHING OPERATIONS
    set_run = ['hash']
    # All message digest operations can use the same setup; need to copy empty
    # Hash object outside of timing run to avoid growing data size with each run
    setup = """\
from __main__ import digest_prime, message
digest = digest_prime.copy()
"""
    
    algo_run = ['RIPEMD160']
    digest_prime = hashes.Hash(hashes.RIPEMD160(), backend=backend)
    trial = Timer("digest.update(message); digest.finalize()", setup)
    algo_run.append(trial.repeat(RUN_COUNT, 1))
    set_run.append(algo_run)
    
    algo_run = ['SHA512']
    digest_prime = hashes.Hash(hashes.SHA512(), backend=backend)
    trial = Timer("digest.update(message); digest.finalize()", setup)
    algo_run.append(trial.repeat(RUN_COUNT, 1))
    set_run.append(algo_run)
    
    algo_run = ['Whirlpool']
    digest_prime = hashes.Hash(hashes.Whirlpool(), backend=backend)
    trial = Timer("digest.update(message); digest.finalize()", setup)
    algo_run.append(trial.repeat(RUN_COUNT, 1))
    set_run.append(algo_run)
    
    lib_run.append(set_run)
    
    result.append(lib_run)
    
    
# ********** ######################## ******************************************
# ********** BEGIN 'PYCRYPTO' LIBRARY ******************************************
# ********** ######################## ******************************************
    
    lib_run = ['PyCrypto']
    
    # BEGIN BLOCK CIPHER OPERATIONS
    set_run = ['block']
    setup = """\
from __main__ import cipher, message, enctext
"""
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['DES3']
    cipher = DES3.new(key, DES3.MODE_CBC, iv8)
    enctext = cipher.encrypt(message)
    enc_run = ['encrypt']
    enc_trial = Timer("cipher.encrypt(message)", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer("cipher.decrypt(enctext)", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['AES']
    cipher = AES.new(key, AES.MODE_CBC, iv16)
    enctext = cipher.encrypt(message)
    enc_run = ['encrypt']
    enc_trial = Timer("cipher.encrypt(message)", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer("cipher.decrypt(enctext)", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['CAST']
    cipher = CAST.new(key, CAST.MODE_CBC, iv8)
    enctext = cipher.encrypt(message)
    enc_run = ['encrypt']
    enc_trial = Timer("cipher.encrypt(message)", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer("cipher.decrypt(enctext)", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    lib_run.append(set_run)
    
    
    # BEGIN STREAM CIPHER OPERATIONS
    set_run = ['stream']
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['ARC4']
    cipher = ARC4.new(key)
    enctext = cipher.encrypt(message)
    enc_run = ['encrypt']
    enc_trial = Timer("cipher.encrypt(message)", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer("cipher.decrypt(enctext)", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['AES-CFB']
    cipher = AES.new(key, AES.MODE_CFB, iv16)
    enctext = cipher.encrypt(message)
    enc_run = ['encrypt']
    enc_trial = Timer("cipher.encrypt(message)", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer("cipher.decrypt(enctext)", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['CAST-CFB']
    cipher = CAST.new(key, CAST.MODE_CFB, iv8)
    enctext = cipher.encrypt(message)
    enc_run = ['encrypt']
    enc_trial = Timer("cipher.encrypt(message)", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer("cipher.decrypt(enctext)", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    lib_run.append(set_run)
    
    
    # BEGIN ASYMMETRIC CIPHER OPERATIONS
    set_run = ['asymmetric']
    
    algo_run = ['RSA']
    # Create key containing both parts
    rsa_key = RSA.generate(2**KEY_EXP)
    enctext = pub_key_encrypt(message, rsa_key, 0)
    enc_run = ['encrypt']
    setup = """\
from __main__ import pub_key_encrypt, rsa_key, message
"""
    enc_trial = Timer("pub_key_encrypt(message, rsa_key, 0)", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    setup = """\
from __main__ import pycrypto_pub_key_decrypt, rsa_key, enctext
"""
    dec_trial = Timer("pycrypto_pub_key_decrypt(enctext, rsa_key)", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    # Encryption alone took several hours utilizing 100% of one CPU core
#    algo_run = ['ElGamal']
#    elgamal_key = ElGamal.generate(2**KEY_EXP, Random.new().read)
#    enctext = pub_key_encrypt(message, elgamal_key, 1)
#    enc_run = ['encrypt']
#    setup = """\
#from __main__ import pub_key_encrypt, elgamal_key, message
#"""
#    enc_trial = Timer("pub_key_encrypt(message, elgamal_key, 1)", setup)
#    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
#    algo_run.append(enc_run)
#    dec_run = ['decrypt']
#    setup = """\
#from __main__ import pycrypto_pub_key_decrypt, elgamal_key, enctext
#"""
#    dec_trial = Timer("pycrypto_pub_key_decrypt(enctext, elgamal_key)", setup)
#    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
#    algo_run.append(dec_run)
#    set_run.append(algo_run)
    
    lib_run.append(set_run)
    
    
    # BEGIN HASHING OPERATIONS
    set_run = ['hash']
    setup = """\
from __main__ import digest_prime, message
digest = digest_prime.copy()
"""
    
    algo_run = ['RIPEMD160']
    digest_prime = RIPEMD.new()
    trial = Timer("digest.update(message)", setup)
    algo_run.append(trial.repeat(RUN_COUNT, 1))
    set_run.append(algo_run)
    
    algo_run = ['SHA512']
    digest_prime = SHA512.new()
    trial = Timer("digest.update(message)", setup)
    algo_run.append(trial.repeat(RUN_COUNT, 1))
    set_run.append(algo_run)
    
    algo_run = ['MD5']
    digest_prime = MD5.new()
    trial = Timer("digest.update(message)", setup)
    algo_run.append(trial.repeat(RUN_COUNT, 1))
    set_run.append(algo_run)
    
    lib_run.append(set_run)
    
    result.append(lib_run)
    
    
# ********** ############################ **************************************
# ********** BEGIN 'PYTHON-GNUPG' LIBRARY **************************************
# ********** ############################ **************************************
    
    lib_run = ['python-gnupg']
    # Setupt the GPG object that will be used for all python-gnupg oprerations
    gpg = GPG(gnupghome='.python-gnupg')
    gpg.encoding = 'utf-8'
    # These commands needed to be run once to generate and save the key
    #input_data = gpg.gen_key_input(key_type="RSA", key_length=2**KEY_EXP)
    #gpg_key = gpg.gen_key(input_data)
    
    # BEGIN BLOCK CIPHER OPERATIONS
    set_run = ['block']
    setup = """\
from __main__ import gpg, message, enctext
"""
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['3DES']
    enctext = gpg.encrypt(message, None, symmetric='3DES',
                          passphrase=PASSPHRASE, armor=False)
    enc_run = ['encrypt']
    enc_trial = Timer(
        "gpg.encrypt(message, None, symmetric='3DES', passphrase=PASSPHRASE, armor=False)",
        setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer(
        "gpg.decrypt(enctext.data, passphrase=PASSPHRASE)",
        setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['AES']
    enctext = gpg.encrypt(message, None, symmetric='AES',
                          passphrase=PASSPHRASE, armor=False)
    enc_run = ['encrypt']
    enc_trial = Timer(
        "gpg.encrypt(message, None, symmetric='AES', passphrase=PASSPHRASE, armor=False)",
        setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer(
        "gpg.decrypt(enctext.data, passphrase=PASSPHRASE)",
        setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    # Create cipher, create cipher text for decryption, time operations, update
    # result with each new operation
    algo_run = ['CAST5']
    enctext = gpg.encrypt(message, None, symmetric='CAST5',
                          passphrase=PASSPHRASE, armor=False)
    enc_run = ['encrypt']
    enc_trial = Timer(
        "gpg.encrypt(message, None, symmetric='CAST5', passphrase=PASSPHRASE, armor=False)",
        setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer(
        "gpg.decrypt(enctext.data, passphrase=PASSPHRASE)",
        setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    lib_run.append(set_run)
    
    
    # Could not find how to add stream ciphers to GnuPG
#    set_run = ['stream']
    
#    algo_run = ['ARC4']
#    enc_run = ['encrypt']
#    algo_run.append(enc_run)
#    dec_run = ['decrypt']
#    algo_run.append(dec_run)
#    set_run.append(algo_run)
#    
#    algo_run = ['AES-CFB']
#    enc_run = ['encrypt']
#    algo_run.append(enc_run)
#    dec_run = ['decrypt']
#    algo_run.append(dec_run)
#    set_run.append(algo_run)
#    
#    algo_run = ['CAST-CFB']
#    enc_run = ['encrypt']
#    algo_run.append(enc_run)
#    dec_run = ['decrypt']
#    algo_run.append(dec_run)
#    set_run.append(algo_run)
#    
#    lib_run.append(set_run)
    
    
    # BEGIN ASYMMETRIC CIPHER OPERATIONS
    set_run = ['asymmetric']
    # Key has already been generated and saved
    setup = """\
from __main__ import gpg, KEY_ID, PASSPHRASE, message, enctext
"""
    
    algo_run = ['rsa']
    enctext = gpg.encrypt(message, 'KEY_ID', always_trust=True)
    enc_run = ['encrypt']
    enc_trial = Timer("gpg.encrypt(message, 'KEY_ID', always_trust=True)", setup)
    enc_run.append(enc_trial.repeat(RUN_COUNT, 1))
    algo_run.append(enc_run)
    dec_run = ['decrypt']
    dec_trial = Timer("gpg.decrypt(enctext.data, passphrase=PASSPHRASE)", setup)
    dec_run.append(dec_trial.repeat(RUN_COUNT, 1))
    algo_run.append(dec_run)
    set_run.append(algo_run)
    
    lib_run.append(set_run)
    
    result.append(lib_run)
    
    
# ********** ####################### *******************************************
# ********** BEGIN 'HASHLIB' LIBRARY *******************************************
# ********** ####################### *******************************************
    
    # python-gnupg does not seem to provide an interface to hash functions
    lib_run = ['hashlib']
    
    # BEGIN HASHING OPERATIONS
    set_run = ['hash']
    setup = """\
from __main__ import message
import hashlib
"""
    
    algo_run = ['sha1']
    trial = Timer("hashlib.sha1(message)", setup)
    algo_run.append(trial.repeat(RUN_COUNT, 1))
    set_run.append(algo_run)
    
    algo_run = ['sha512']
    trial = Timer("hashlib.sha512(message)", setup)
    algo_run.append(trial.repeat(RUN_COUNT, 1))
    set_run.append(algo_run)
    
    algo_run = ['md5']
    trial = Timer("hashlib.md5(message)", setup)
    algo_run.append(trial.repeat(RUN_COUNT, 1))
    set_run.append(algo_run)
    
    lib_run.append(set_run)
    
    result.append(lib_run)
    
    print(result)
