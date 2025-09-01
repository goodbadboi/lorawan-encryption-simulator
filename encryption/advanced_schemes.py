#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Encryption Schemes Module

Provides more modern encryption algorithms, including national cryptographic algorithms and advanced symmetric encryption.
"""

import time
import hashlib
import os
from typing import Tuple, Optional
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256, SHA3_256
from Crypto.Protocol.KDF import PBKDF2

from .schemes import EncryptionScheme, LoRaWANPacket


class AESGCM(EncryptionScheme):
    """AES-GCM encryption scheme (authenticated encryption)"""
    
    def __init__(self):
        super().__init__("AES-GCM")
    
    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        start_time = time.perf_counter_ns()
        
        # Generate 12-byte nonce
        nonce = get_random_bytes(12)
        
        # Create AES-GCM cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Add associated data
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big')
        cipher.update(aad)
        
        # Encrypt
        ciphertext, tag = cipher.encrypt_and_digest(packet.payload)
        
        packet.encrypted_payload = ciphertext
        packet.mic = tag
        packet.nonce = nonce
        
        end_time = time.perf_counter_ns()
        return packet, end_time - start_time
    
    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.encrypted_payload is None or packet.nonce is None or packet.mic is None:
            raise ValueError("Missing encrypted payload, nonce, or MIC")
        
        # Create AES-GCM cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=packet.nonce)
        
        # Add associated data
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big')
        cipher.update(aad)
        
        try:
            # Decrypt and verify
            decrypted = cipher.decrypt_and_verify(packet.encrypted_payload, packet.mic)
            return decrypted
        except ValueError:
            raise ValueError("Authentication failed")
    
    def compute_mic(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.mic is None:
            raise ValueError("No MIC available")
        return packet.mic
    
    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        try:
            self.decrypt(packet, key)
            return True
        except ValueError:
            return False


class ChaCha20Poly1305_256(EncryptionScheme):
    """ChaCha20-Poly1305 with 256-bit key"""
    
    def __init__(self):
        super().__init__("ChaCha20-Poly1305-256")
    
    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        start_time = time.perf_counter_ns()
        
        # Properly derive 256-bit key using HKDF instead of truncation/zero-padding
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=packet.dev_eui,
            info=b"ChaCha20-256-Key",
            backend=default_backend()
        )
        derived_key = hkdf.derive(key)
        
        # Generate structured nonce
        nonce = self._generate_nonce(packet.dev_eui, packet.fcnt)
        
        # Create ChaCha20-Poly1305 cipher with derived key
        from Crypto.Cipher import ChaCha20_Poly1305
        cipher = ChaCha20_Poly1305.new(key=derived_key, nonce=nonce)
        
        # Add associated data
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big')
        cipher.update(aad)
        
        # Encrypt
        ciphertext = cipher.encrypt(packet.payload)
        tag = cipher.digest()
        
        packet.encrypted_payload = ciphertext
        packet.mic = tag
        packet.nonce = nonce
        
        end_time = time.perf_counter_ns()
        return packet, end_time - start_time
    
    def _generate_nonce(self, dev_eui: bytes, fcnt: int) -> bytes:
        """Generate structured nonce for ChaCha20-Poly1305"""
        dev_addr = dev_eui[:4]  # DevAddr from dev_eui
        fcnt_bytes = fcnt.to_bytes(4, 'little')  # Little-endian for nonce
        random_part = get_random_bytes(4)  # 4 bytes random for uniqueness
        return dev_addr + fcnt_bytes + random_part
    
    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.encrypted_payload is None or packet.nonce is None or packet.mic is None:
            raise ValueError("Missing encrypted payload, nonce, or MIC")
        
        # Properly derive 256-bit key using HKDF
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=packet.dev_eui,
            info=b"ChaCha20-256-Key",
            backend=default_backend()
        )
        derived_key = hkdf.derive(key)
        
        # Create ChaCha20-Poly1305 cipher with derived key
        from Crypto.Cipher import ChaCha20_Poly1305
        cipher = ChaCha20_Poly1305.new(key=derived_key, nonce=packet.nonce)
        
        # Add associated data
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big')
        cipher.update(aad)
        
        try:
            # Decrypt
            decrypted = cipher.decrypt(packet.encrypted_payload)
            # Verify authentication tag
            cipher.verify(packet.mic)
            return decrypted
        except ValueError:
            raise ValueError("MAC verification failed")
    
    def compute_mic(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.mic is None:
            raise ValueError("No MIC available")
        return packet.mic
    
    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        try:
            self.decrypt(packet, key)
            return True
        except ValueError:
            return False


class SM4(EncryptionScheme):
    """National SM4 encryption scheme (PLACEHOLDER implementation)"""
    
    def __init__(self):
        super().__init__("SM4")
    
    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        start_time = time.perf_counter_ns()
        
        # WARNING: This is a placeholder implementation using AES-CBC
        # In real applications, true SM4 implementation should be used
        # For demonstration purposes only - not suitable for production
        
        # Use AES-CBC as SM4 replacement implementation
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(packet.payload, AES.block_size)
        ct_bytes = cipher.encrypt(padded_data)
        
        packet.encrypted_payload = iv + ct_bytes
        
        # Calculate and set MIC
        packet.mic = self.compute_mic(packet, key)
        
        end_time = time.perf_counter_ns()
        return packet, end_time - start_time
    
    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.encrypted_payload is None:
            raise ValueError("No encrypted payload to decrypt")
        
        iv = packet.encrypted_payload[:16]
        ct = packet.encrypted_payload[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        try:
            decrypted = unpad(cipher.decrypt(ct), AES.block_size)
            return decrypted
        except ValueError:
            raise ValueError("Padding is incorrect")
    
    def compute_mic(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        data = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + packet.payload
        return hashlib.sha256(data + key).digest()[:4]
    
    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        return packet.mic == self.compute_mic(packet, key)


class AESCCM(EncryptionScheme):
    """AES-CCM encryption scheme (authenticated encryption)"""
    
    def __init__(self):
        super().__init__("AES-CCM")
    
    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        start_time = time.perf_counter_ns()
        
        # Generate nonce
        nonce = get_random_bytes(12)
        
        # Create AES-CCM cipher
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
        
        # Add associated data
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big')
        cipher.update(aad)
        
        # Encrypt
        ciphertext, tag = cipher.encrypt_and_digest(packet.payload)
        
        packet.encrypted_payload = ciphertext
        packet.mic = tag
        packet.nonce = nonce
        
        end_time = time.perf_counter_ns()
        return packet, end_time - start_time
    
    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.encrypted_payload is None or packet.nonce is None or packet.mic is None:
            raise ValueError("Missing encrypted payload, nonce, or MIC")
        
        # Create AES-CCM cipher
        cipher = AES.new(key, AES.MODE_CCM, nonce=packet.nonce)
        
        # Add associated data
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big')
        cipher.update(aad)
        
        try:
            # Decrypt and verify
            decrypted = cipher.decrypt_and_verify(packet.encrypted_payload, packet.mic)
            return decrypted
        except ValueError:
            raise ValueError("Authentication failed")
    
    def compute_mic(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.mic is None:
            raise ValueError("No MIC available")
        return packet.mic
    
    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        try:
            self.decrypt(packet, key)
            return True
        except ValueError:
            return False


def get_advanced_schemes():
    """Get all advanced encryption schemes"""
    return [
        AESGCM(),
        ChaCha20Poly1305_256(),
        SM4(),
        AESCCM()
    ]
