#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Post-Quantum Cryptography Encryption Schemes

Provides post-quantum secure encryption schemes based on lattice cryptography and hash signatures.
"""

import time
import random
import hashlib
import struct
from typing import Tuple, List, Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod

from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, SHA3_256
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .schemes import EncryptionScheme, LoRaWANPacket


class LatticeBasedScheme(EncryptionScheme):
    """Lattice-based cryptography encryption scheme (PLACEHOLDER - KEM-DEM construction)"""
    
    def __init__(self):
        super().__init__("Lattice-Based")
        self.lattice_dimension = 256
        self.modulus = 12289  # Common lattice parameters
    
    def _simulate_kem_encapsulation(self) -> Tuple[bytes, bytes]:
        """Simulate KEM encapsulation (placeholder)"""
        # Generate simulated public key and shared secret
        public_key = get_random_bytes(32)
        shared_secret = get_random_bytes(32)
        return public_key, shared_secret
    
    def _simulate_kem_decapsulation(self, public_key: bytes) -> bytes:
        """Simulate KEM decapsulation (placeholder)"""
        # Simulate shared secret recovery
        return hashlib.sha256(public_key).digest()
    
    def _derive_aead_key(self, shared_secret: bytes, dev_eui: bytes) -> bytes:
        """Derive AEAD key using HKDF"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=dev_eui,
            info=b"Lattice-KEM-AEAD",
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)
    
    def _generate_nonce(self, dev_eui: bytes, fcnt: int, direction: int = 0) -> bytes:
        """Generate structured nonce for ChaCha20-Poly1305"""
        dev_addr = dev_eui[:4]
        fcnt_bytes = fcnt.to_bytes(4, 'little')
        dir_byte = direction.to_bytes(1, 'little')
        random_part = get_random_bytes(3)
        return dev_addr + fcnt_bytes + dir_byte + random_part
    
    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        start_time = time.perf_counter_ns()
        
        # 1. KEM encapsulation
        ephemeral_public_key, shared_secret = self._simulate_kem_encapsulation()
        
        # 2. Derive AEAD key
        aead_key = self._derive_aead_key(shared_secret, packet.dev_eui)
        
        # 3. ChaCha20-Poly1305 AEAD encryption
        nonce = self._generate_nonce(packet.dev_eui, packet.fcnt, direction=0)
        cipher = ChaCha20_Poly1305.new(key=aead_key, nonce=nonce)
        
        # Add associated data (AAD)
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00'
        cipher.update(aad)
        
        # Encrypt and get tag
        ciphertext = cipher.encrypt(packet.payload)
        tag = cipher.digest()
        
        # 4. Combine: ephemeral_pubkey + ciphertext + tag
        packet.encrypted_payload = ephemeral_public_key + ciphertext + tag
        packet.mic = tag
        packet.nonce = nonce
        
        end_time = time.perf_counter_ns()
        return packet, end_time - start_time
    
    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.encrypted_payload is None:
            raise ValueError("No encrypted payload to decrypt")
        
        # Parse: ephemeral_pubkey(32) + ciphertext + tag(16)
        ephemeral_public_key = packet.encrypted_payload[:32]
        tag = packet.encrypted_payload[-16:]
        ciphertext = packet.encrypted_payload[32:-16]
        
        # 1. KEM decapsulation
        shared_secret = self._simulate_kem_decapsulation(ephemeral_public_key)
        
        # 2. Derive AEAD key
        aead_key = self._derive_aead_key(shared_secret, packet.dev_eui)
        
        # 3. ChaCha20-Poly1305 AEAD decryption
        if packet.nonce is None:
            raise ValueError("No nonce available for decryption")
        
        cipher = ChaCha20_Poly1305.new(key=aead_key, nonce=packet.nonce)
        
        # Add associated data (AAD)
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00'
        cipher.update(aad)
        
        try:
            # Decrypt and verify tag
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except ValueError:
            raise ValueError("AEAD verification failed")
    
    def compute_mic(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.mic is not None:
            return packet.mic
        # Fallback
        data = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + packet.payload
        return hashlib.sha256(data + key).digest()[:16]
    
    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        try:
            self.decrypt(packet, key)
            return True
        except Exception:
            return False


class KyberScheme(EncryptionScheme):
    """Kyber post-quantum encryption scheme (simplified implementation - PLACEHOLDER)"""
    
    def __init__(self):
        super().__init__("Kyber")
        self.n = 256
        self.q = 3329
        self.k = 2
    
    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        start_time = time.perf_counter_ns()
        
        # WARNING: This is a placeholder implementation for demonstration purposes only
        # In a real implementation, this should use proper Kyber KEM + AEAD encryption
        
        # Generate ephemeral key pair for KEM
        ephemeral_public_key, ephemeral_secret_key = self._generate_keypair()
        
        # Simulate KEM encapsulation (in real implementation, this would be proper Kyber)
        shared_secret = self._simulate_kem_encapsulation(ephemeral_public_key)
        
        # Derive AEAD key using HKDF
        aead_key = self._derive_aead_key(shared_secret, packet.dev_eui)
        
        # Use ChaCha20-Poly1305 for actual encryption (KEM-DEM construction)
        nonce = self._generate_nonce(packet.dev_eui, packet.fcnt)
        cipher = ChaCha20_Poly1305.new(key=aead_key, nonce=nonce)
        
        # Add associated data
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big')
        cipher.update(aad)
        
        # Encrypt payload
        ciphertext = cipher.encrypt(packet.payload)
        tag = cipher.digest()
        
        # Combine: ephemeral_pubkey + ciphertext + tag
        packet.encrypted_payload = ephemeral_public_key + ciphertext + tag
        packet.mic = tag
        packet.nonce = nonce
        
        end_time = time.perf_counter_ns()
        return packet, end_time - start_time
    
    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.encrypted_payload is None or packet.nonce is None:
            raise ValueError("No encrypted payload or nonce to decrypt")
        
        # Parse: ephemeral_pubkey + ciphertext + tag
        ephemeral_pubkey = packet.encrypted_payload[:32]
        tag = packet.encrypted_payload[-16:]
        ciphertext = packet.encrypted_payload[32:-16]
        
        # Simulate KEM decapsulation
        shared_secret = self._simulate_kem_decapsulation(ephemeral_pubkey, key)
        
        # Derive AEAD key
        aead_key = self._derive_aead_key(shared_secret, packet.dev_eui)
        
        # Decrypt with ChaCha20-Poly1305
        cipher = ChaCha20_Poly1305.new(key=aead_key, nonce=packet.nonce)
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big')
        cipher.update(aad)
        
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except ValueError:
            raise ValueError("AEAD verification failed")
    
    def _simulate_kem_encapsulation(self, public_key: bytes) -> bytes:
        """Simulate KEM encapsulation (placeholder)"""
        return hashlib.sha256(public_key + get_random_bytes(16)).digest()
    
    def _simulate_kem_decapsulation(self, public_key: bytes, secret_key: bytes) -> bytes:
        """Simulate KEM decapsulation (placeholder)"""
        return hashlib.sha256(public_key + secret_key).digest()
    
    def _derive_aead_key(self, shared_secret: bytes, dev_eui: bytes) -> bytes:
        """Derive AEAD key using HKDF"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=dev_eui,
            info=b"Kyber-AEAD",
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)
    
    def _generate_nonce(self, dev_eui: bytes, fcnt: int) -> bytes:
        """Generate nonce for AEAD"""
        dev_addr = dev_eui[:4]
        fcnt_bytes = fcnt.to_bytes(4, 'little')
        random_part = get_random_bytes(4)
        return dev_addr + fcnt_bytes + random_part
    
    def _generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate key pair"""
        # Simplified implementation
        public_key = get_random_bytes(32)
        secret_key = get_random_bytes(32)
        return public_key, secret_key
    
    def _hash_to_poly(self, data: bytes) -> bytes:
        """Hash to polynomial"""
        return hashlib.sha256(data).digest()
    
    def compute_mic(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        """Calculate message integrity code"""
        data = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + packet.payload
        return hashlib.sha256(data + key).digest()[:4]
    
    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        """Verify message integrity code"""
        return packet.mic == self.compute_mic(packet, key)


class DilithiumScheme(EncryptionScheme):
    """Dilithium post-quantum signature scheme (PLACEHOLDER - Signature + AEAD)"""
    
    def __init__(self):
        super().__init__("Dilithium")
        self.n = 256
        self.q = 8380417
        self.k = 4
        self.l = 2
    
    def _simulate_signature(self, message: bytes, secret_key: bytes) -> bytes:
        """Simulate Dilithium signature (placeholder)"""
        # Simplified signature simulation
        return hashlib.sha256(message + secret_key).digest()[:64]
    
    def _simulate_verify_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Simulate Dilithium signature verification (placeholder)"""
        # Simplified verification simulation
        expected = hashlib.sha256(message + public_key).digest()[:64]
        return signature == expected
    
    def _generate_nonce(self, dev_eui: bytes, fcnt: int, direction: int = 0) -> bytes:
        """Generate structured nonce for ChaCha20-Poly1305"""
        dev_addr = dev_eui[:4]
        fcnt_bytes = fcnt.to_bytes(4, 'little')
        dir_byte = direction.to_bytes(1, 'little')
        random_part = get_random_bytes(3)
        return dev_addr + fcnt_bytes + dir_byte + random_part
    
    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        start_time = time.perf_counter_ns()
        
        # 1. Generate signature key pair
        public_key, secret_key = self._generate_keypair()
        
        # 2. Sign the message
        message_to_sign = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + packet.payload
        signature = self._simulate_signature(message_to_sign, secret_key)
        
        # 3. ChaCha20-Poly1305 AEAD encryption
        nonce = self._generate_nonce(packet.dev_eui, packet.fcnt, direction=0)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        
        # Add associated data (AAD) including signature
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00' + signature
        cipher.update(aad)
        
        # Encrypt and get tag
        ciphertext = cipher.encrypt(packet.payload)
        tag = cipher.digest()
        
        # 4. Combine: signature + public_key + ciphertext + tag
        packet.encrypted_payload = signature + public_key + ciphertext + tag
        packet.mic = tag
        packet.nonce = nonce
        
        end_time = time.perf_counter_ns()
        return packet, end_time - start_time
    
    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.encrypted_payload is None:
            raise ValueError("No encrypted payload to decrypt")
        
        # Parse: signature(64) + public_key(32) + ciphertext + tag(16)
        signature = packet.encrypted_payload[:64]
        public_key = packet.encrypted_payload[64:96]
        tag = packet.encrypted_payload[-16:]
        ciphertext = packet.encrypted_payload[96:-16]
        
        # 1. Verify signature
        message_to_verify = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + packet.payload
        if not self._simulate_verify_signature(message_to_verify, signature, public_key):
            raise ValueError("Signature verification failed")
        
        # 2. ChaCha20-Poly1305 AEAD decryption
        if packet.nonce is None:
            raise ValueError("No nonce available for decryption")
        
        cipher = ChaCha20_Poly1305.new(key=key, nonce=packet.nonce)
        
        # Add associated data (AAD) including signature
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00' + signature
        cipher.update(aad)
        
        try:
            # Decrypt and verify tag
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except ValueError:
            raise ValueError("AEAD verification failed")
    
    def _generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate signature key pair"""
        # Simplified implementation
        public_key = get_random_bytes(32)
        secret_key = get_random_bytes(32)
        return public_key, secret_key
    
    def compute_mic(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.mic is not None:
            return packet.mic
        # Fallback
        data = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + packet.payload
        return hashlib.sha256(data + key).digest()[:16]
    
    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        try:
            self.decrypt(packet, key)
            return True
        except Exception:
            return False


class SPHINCSPlusScheme(EncryptionScheme):
    """SPHINCS+ post-quantum signature scheme (PLACEHOLDER - Signature + AEAD)"""
    
    def __init__(self):
        super().__init__("SPHINCS+")
        self.hash_size = 32
        self.tree_height = 10
    
    def _simulate_sphincs_signature(self, message: bytes, secret_key: bytes) -> bytes:
        """Simulate SPHINCS+ signature (placeholder)"""
        # Simplified signature simulation
        return hashlib.sha256(message + secret_key + b"SPHINCS").digest()[:128]
    
    def _simulate_verify_sphincs_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Simulate SPHINCS+ signature verification (placeholder)"""
        # Simplified verification simulation
        expected = hashlib.sha256(message + public_key + b"SPHINCS").digest()[:128]
        return signature == expected
    
    def _generate_nonce(self, dev_eui: bytes, fcnt: int, direction: int = 0) -> bytes:
        """Generate structured nonce for ChaCha20-Poly1305"""
        dev_addr = dev_eui[:4]
        fcnt_bytes = fcnt.to_bytes(4, 'little')
        dir_byte = direction.to_bytes(1, 'little')
        random_part = get_random_bytes(3)
        return dev_addr + fcnt_bytes + dir_byte + random_part
    
    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        start_time = time.perf_counter_ns()
        
        # 1. Generate SPHINCS+ key pair
        public_key, secret_key = self._generate_sphincs_keypair()
        
        # 2. Sign the message
        message_to_sign = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + packet.payload
        signature = self._simulate_sphincs_signature(message_to_sign, secret_key)
        
        # 3. ChaCha20-Poly1305 AEAD encryption
        nonce = self._generate_nonce(packet.dev_eui, packet.fcnt, direction=0)
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        
        # Add associated data (AAD) including signature
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00' + signature
        cipher.update(aad)
        
        # Encrypt and get tag
        ciphertext = cipher.encrypt(packet.payload)
        tag = cipher.digest()
        
        # 4. Combine: signature + public_key + ciphertext + tag
        packet.encrypted_payload = signature + public_key + ciphertext + tag
        packet.mic = tag
        packet.nonce = nonce
        
        end_time = time.perf_counter_ns()
        return packet, end_time - start_time
    
    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.encrypted_payload is None:
            raise ValueError("No encrypted payload to decrypt")
        
        # Parse: signature(128) + public_key(32) + ciphertext + tag(16)
        signature = packet.encrypted_payload[:128]
        public_key = packet.encrypted_payload[128:160]
        tag = packet.encrypted_payload[-16:]
        ciphertext = packet.encrypted_payload[160:-16]
        
        # 1. Verify signature
        message_to_verify = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + packet.payload
        if not self._simulate_verify_sphincs_signature(message_to_verify, signature, public_key):
            raise ValueError("SPHINCS+ signature verification failed")
        
        # 2. ChaCha20-Poly1305 AEAD decryption
        if packet.nonce is None:
            raise ValueError("No nonce available for decryption")
        
        cipher = ChaCha20_Poly1305.new(key=key, nonce=packet.nonce)
        
        # Add associated data (AAD) including signature
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00' + signature
        cipher.update(aad)
        
        try:
            # Decrypt and verify tag
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except ValueError:
            raise ValueError("AEAD verification failed")
    
    def _generate_sphincs_keypair(self) -> Tuple[bytes, bytes]:
        """Generate SPHINCS+ key pair"""
        # Simplified implementation
        public_key = get_random_bytes(32)
        secret_key = get_random_bytes(32)
        return public_key, secret_key
    
    def compute_mic(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.mic is not None:
            return packet.mic
        # Fallback
        data = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + packet.payload
        return hashlib.sha256(data + key).digest()[:16]
    
    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        try:
            self.decrypt(packet, key)
            return True
        except Exception:
            return False


# Update encryption scheme factory functions
def get_post_quantum_schemes() -> List[EncryptionScheme]:
    """Get all post-quantum encryption schemes"""
    return [
        LatticeBasedScheme(),
        KyberScheme(),
        DilithiumScheme(),
        SPHINCSPlusScheme()
    ]


def get_all_schemes_with_post_quantum() -> List[EncryptionScheme]:
    """Get all encryption schemes (including post-quantum)"""
    from .schemes import get_all_schemes
    return get_all_schemes() + get_post_quantum_schemes() 