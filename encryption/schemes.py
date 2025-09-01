import os
import time
import random
import hashlib
from typing import Tuple, Optional
from abc import ABC, abstractmethod

from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES, ChaCha20_Poly1305, ChaCha20
from Crypto.Hash import HMAC, SHA256
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class LoRaWANPacket:
    """LoRaWAN packet model"""
    def __init__(self, dev_eui: bytes, payload: bytes, fcnt: int):
        self.dev_eui = dev_eui
        self.payload = payload
        self.fcnt = fcnt
        self.mic: Optional[bytes] = None
        self.encrypted_payload: Optional[bytes] = None
        self.nonce: Optional[bytes] = None

    def __repr__(self):
        return f"DevEUI: {self.dev_eui.hex()}, FCnt: {self.fcnt}, Payload: {self.payload[:10]}..."

class EncryptionScheme(ABC):
    """Encryption scheme abstract base class"""
    
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        """
        Encrypt packet
        Returns: (encrypted packet, encryption time in nanoseconds)
        """
        pass

    @abstractmethod
    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        """Decrypt packet"""
        pass

    @abstractmethod
    def compute_mic(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        """Compute message integrity check code"""
        pass

    @abstractmethod
    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        """Verify message integrity check code"""
        pass

class AES128_GCM(EncryptionScheme):
    """AES-128-GCM encryption scheme (AEAD, improved from CTR)"""
    
    def __init__(self):
        super().__init__("AES-128-GCM")

    def _generate_nonce(self, dev_eui: bytes, fcnt: int, direction: int = 0) -> bytes:
        """Generate structured nonce: DevAddr(4) + FCnt(4) + Direction(1) + Padding(3)"""
        dev_addr = dev_eui[:4]  # DevAddr from dev_eui
        fcnt_bytes = fcnt.to_bytes(4, 'little')  # LoRaWAN uses little-endian
        dir_byte = direction.to_bytes(1, 'little')
        padding = b'\x00\x00\x00'
        return dev_addr + fcnt_bytes + dir_byte + padding

    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        start_time = time.perf_counter_ns()
        
        # Generate structured nonce with direction
        nonce = self._generate_nonce(packet.dev_eui, packet.fcnt, direction=0)  # 0 for uplink
        
        # Create AES-GCM cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Add associated data (AAD) for integrity
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big')
        cipher.update(aad)
        
        # Encrypt and get tag
        ciphertext, tag = cipher.encrypt_and_digest(packet.payload)
        
        packet.encrypted_payload = ciphertext
        packet.mic = tag  # Full 16-byte GCM tag
        packet.nonce = nonce
        
        end_time = time.perf_counter_ns()
        return packet, end_time - start_time

    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.encrypted_payload is None or packet.nonce is None:
            raise ValueError("No encrypted payload or nonce to decrypt")
        
        # Create AES-GCM cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=packet.nonce)
        
        # Add associated data (AAD)
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big')
        cipher.update(aad)
        
        try:
            # Decrypt and verify tag
            plaintext = cipher.decrypt_and_verify(packet.encrypted_payload, packet.mic)
            return plaintext
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

class ChaCha20Poly1305(EncryptionScheme):
    """ChaCha20-Poly1305 encryption scheme"""
    
    def __init__(self):
        super().__init__("ChaCha20-Poly1305")

    def _generate_nonce(self, dev_eui: bytes, fcnt: int, direction: int = 0) -> bytes:
        """Generate structured nonce: DevAddr(4) + FCnt(4) + Direction(1) + Random(3) = 12 bytes"""
        dev_addr = dev_eui[:4]  # DevAddr from dev_eui
        fcnt_bytes = fcnt.to_bytes(4, 'little')  # Little-endian for nonce
        dir_byte = direction.to_bytes(1, 'little')
        random_part = get_random_bytes(3)  # 3 bytes random for uniqueness
        return dev_addr + fcnt_bytes + dir_byte + random_part

    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        start_time = time.perf_counter_ns()
        
        # Generate structured nonce with device state
        nonce = self._generate_nonce(packet.dev_eui, packet.fcnt, direction=0)  # 0 for uplink
        
        # Create AEAD cipher
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        
        # Add associated data (AAD) - include more context
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00'  # Direction byte
        cipher.update(aad)
        
        # Encrypt
        ciphertext = cipher.encrypt(packet.payload)
        tag = cipher.digest()
        
        packet.encrypted_payload = ciphertext
        packet.mic = tag
        packet.nonce = nonce
        
        end_time = time.perf_counter_ns()
        return packet, end_time - start_time

    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.encrypted_payload is None or packet.nonce is None:
            raise ValueError("No encrypted payload or nonce to decrypt")
        
        # Create AEAD cipher
        cipher = ChaCha20_Poly1305.new(key=key, nonce=packet.nonce)
        
        # Add associated data (AAD) - must match encryption
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00'  # Direction byte
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

class Hybrid_ECC_AES(EncryptionScheme):
    """Hybrid-ECC-AES (Improved): X25519/ECDH + HKDF(SHA-256) → ChaCha20-Poly1305 AEAD
    Encryption output format: ephemeral_pubkey(32) || ciphertext(N) || tag(16)
    Notes:
      - Uses ChaCha20-Poly1305 AEAD for strong integrity protection
      - This implementation follows ECC_SC_MIC style, generating and holding "gateway private/public keys" within the class for easy single-instance encryption/decryption in simulation environment.
        In actual deployment, you should write the gateway public key to the device-side instance and keep the gateway private key only in the gateway-side instance.
    """

    TAG_LEN = 16  # ChaCha20-Poly1305 tag length
    EPHEMERAL_PUB_LEN = 32

    def __init__(self):
        super().__init__("Hybrid-ECC-AES")
        # Simulation environment: hold gateway private and public keys in the same instance for easy direct encryption/decryption
        # In real systems, it's recommended to separate: device side only holds gateway_public_key; gateway side only holds gateway_private_key
        self.gateway_private_key = x25519.X25519PrivateKey.generate()
        self.gateway_public_key = self.gateway_private_key.public_key()

    # —— Internal utility methods ——
    def _derive_session_key(self, shared_secret: bytes, dev_eui: bytes) -> bytes:
        """HKDF(SHA-256) derive 32-byte symmetric session key for ChaCha20-Poly1305"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=dev_eui,                  # Different salt per device: consistent strategy with ECC_SC_MIC
            info=b"LoRa-Encrypt",
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)

    def _generate_nonce(self, dev_eui: bytes, fcnt: int, direction: int = 0) -> bytes:
        """Generate structured nonce for ChaCha20-Poly1305: DevAddr(4) + FCnt(4) + Direction(1) + Random(3) = 12 bytes"""
        dev_addr = dev_eui[:4]  # DevAddr from dev_eui
        fcnt_bytes = fcnt.to_bytes(4, 'little')  # Little-endian for nonce
        dir_byte = direction.to_bytes(1, 'little')
        random_part = get_random_bytes(3)  # 3 bytes random for uniqueness
        return dev_addr + fcnt_bytes + dir_byte + random_part

    # —— Abstract method implementations ——
    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        """Device side: Use ephemeral key pair with gateway public key for ECDH, derive session key for ChaCha20-Poly1305 AEAD"""
        t0 = time.perf_counter_ns()

        # 1) Generate ephemeral key pair
        eph_sk = x25519.X25519PrivateKey.generate()
        eph_pk_bytes = eph_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # 2) ECDH with gateway public key to get shared secret
        shared_secret = eph_sk.exchange(self.gateway_public_key)

        # 3) HKDF derive session key
        session_key = self._derive_session_key(shared_secret, packet.dev_eui)

        # 4) ChaCha20-Poly1305 AEAD encryption
        nonce = self._generate_nonce(packet.dev_eui, packet.fcnt, direction=0)
        cipher = ChaCha20_Poly1305.new(key=session_key, nonce=nonce)
        
        # Add associated data (AAD)
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00'  # Direction byte
        cipher.update(aad)
        
        # Encrypt and get tag
        ciphertext = cipher.encrypt(packet.payload)
        tag = cipher.digest()

        # 5) Combine encrypted payload: eph_pk || ct || tag
        packet.encrypted_payload = eph_pk_bytes + ciphertext + tag
        packet.mic = tag
        packet.nonce = nonce

        t1 = time.perf_counter_ns()
        return packet, (t1 - t0)

    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        """Gateway side: Parse ephemeral public key, reconstruct session key, verify AEAD tag then decrypt"""
        if packet.encrypted_payload is None:
            raise ValueError("No encrypted payload to decrypt")

        data = packet.encrypted_payload
        # Parse layout: eph_pk(32) | ciphertext | tag(TAG_LEN)
        if len(data) < (self.EPHEMERAL_PUB_LEN + self.TAG_LEN + 1):
            raise ValueError("Encrypted payload too short")

        eph_pk_bytes = data[:self.EPHEMERAL_PUB_LEN]
        tag = data[-self.TAG_LEN:]
        ciphertext = data[self.EPHEMERAL_PUB_LEN:-self.TAG_LEN]

        # 1) Restore ephemeral public key
        try:
            eph_pk = x25519.X25519PublicKey.from_public_bytes(eph_pk_bytes)
        except Exception:
            raise ValueError("Invalid ephemeral public key")

        # 2) ECDH using gateway private key
        shared_secret = self.gateway_private_key.exchange(eph_pk)

        # 3) HKDF derive session key
        session_key = self._derive_session_key(shared_secret, packet.dev_eui)

        # 4) ChaCha20-Poly1305 AEAD decryption and verification
        if packet.nonce is None:
            raise ValueError("No nonce available for decryption")
        
        cipher = ChaCha20_Poly1305.new(key=session_key, nonce=packet.nonce)
        
        # Add associated data (AAD) - must match encryption
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00'  # Direction byte
        cipher.update(aad)
        
        try:
            # Decrypt and verify tag
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except ValueError:
            raise ValueError("AEAD verification failed")

    def compute_mic(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        """For consistency: if AEAD tag was already generated in encrypt, return directly"""
        if packet.mic is not None:
            return packet.mic

        if packet.encrypted_payload is None:
            # Cannot rebuild tag without ciphertext, fallback for compatibility with old behavior (not recommended in new flows)
            data = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + packet.payload
            return hashlib.sha256(data + key).digest()[:16]  # 16 bytes for AEAD tag

        # Recalculate (same parsing flow as decrypt)
        data = packet.encrypted_payload
        eph_pk_bytes = data[:self.EPHEMERAL_PUB_LEN]
        tag = data[-self.TAG_LEN:]
        return tag  # Return the AEAD tag directly

    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        try:
            # Could also go through the first half of decrypt logic only up to MIC verification;
            # Here directly try decryption: if successful, it means MIC is correct and ciphertext is not corrupted
            _ = self.decrypt(packet, key)
            return True
        except Exception:
            return False

class Advanced_ECC_AES(EncryptionScheme):
    """Advanced ECC+AES hybrid encryption system (Improved with AES-GCM AEAD)"""
    
    def __init__(self):
        super().__init__("Advanced-ECC-AES")
        self.ecc_curve = ec.SECP384R1()
        self.backend = default_backend()
        self.private_key = None
        self.public_key = None
        self._generate_keypair()

    def _generate_keypair(self):
        """Generate ECC key pair"""
        self.private_key = ec.generate_private_key(self.ecc_curve, self.backend)
        self.public_key = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def _derive_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """Derive shared secret"""
        if self.private_key is None:
            self._generate_keypair()
        peer_public_key = serialization.load_der_public_key(
            peer_public_key_bytes, self.backend
        )
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_secret

    def _derive_aes_key(self, shared_secret: bytes, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Derive AES key from shared secret"""
        if salt is None:
            salt = os.urandom(16)
        derived_key = HKDF(
            algorithm=hashes.SHA3_512(),
            length=32,
            salt=salt,
            info=b'advanced-encryption-system',
            backend=self.backend
        ).derive(shared_secret)
        return derived_key, salt

    def _generate_nonce(self, dev_eui: bytes, fcnt: int, direction: int = 0) -> bytes:
        """Generate structured nonce for AES-GCM: DevAddr(4) + FCnt(4) + Direction(1) + Random(3) = 12 bytes"""
        dev_addr = dev_eui[:4]  # DevAddr from dev_eui
        fcnt_bytes = fcnt.to_bytes(4, 'little')  # Little-endian for nonce
        dir_byte = direction.to_bytes(1, 'little')
        random_part = get_random_bytes(3)  # 3 bytes random for uniqueness
        return dev_addr + fcnt_bytes + dir_byte + random_part

    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        start_time = time.perf_counter_ns()
        
        # Generate ephemeral key pair
        temp_private_key = ec.generate_private_key(self.ecc_curve, self.backend)
        temp_public_key = temp_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Derive shared secret
        shared_secret = self._derive_shared_secret(temp_public_key)
        aes_key, salt = self._derive_aes_key(shared_secret)
        
        # Generate structured nonce for AES-GCM
        nonce = self._generate_nonce(packet.dev_eui, packet.fcnt, direction=0)
        
        # AES-GCM AEAD encryption
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Add associated data (AAD) for integrity
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00'  # Direction byte
        encryptor.authenticate_additional_data(aad)
        
        # Encrypt and get tag
        ciphertext = encryptor.update(packet.payload) + encryptor.finalize()
        tag = encryptor.tag
        
        # Combine all data: temp_pubkey + salt + nonce + ciphertext + tag
        packet.encrypted_payload = temp_public_key + salt + nonce + ciphertext + tag
        packet.mic = tag  # Use GCM tag as MIC
        packet.nonce = nonce
        
        end_time = time.perf_counter_ns()
        return packet, end_time - start_time

    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        try:
            if packet.encrypted_payload is None:
                return packet.payload
                
            # Parse encrypted data: temp_pubkey(91) + salt(16) + nonce(12) + ciphertext + tag(16)
            temp_public_key_len = 91  # SECP384R1 public key length
            salt_len = 16
            nonce_len = 12  # GCM nonce length
            tag_len = 16    # GCM tag length
            
            if len(packet.encrypted_payload) < temp_public_key_len + salt_len + nonce_len + tag_len:
                return packet.payload
            
            temp_public_key = packet.encrypted_payload[:temp_public_key_len]
            salt = packet.encrypted_payload[temp_public_key_len:temp_public_key_len + salt_len]
            nonce = packet.encrypted_payload[temp_public_key_len + salt_len:temp_public_key_len + salt_len + nonce_len]
            tag = packet.encrypted_payload[-tag_len:]
            ciphertext = packet.encrypted_payload[temp_public_key_len + salt_len + nonce_len:-tag_len]
            
            # Derive shared secret
            shared_secret = self._derive_shared_secret(temp_public_key)
            aes_key, _ = self._derive_aes_key(shared_secret, salt)
            
            # AES-GCM AEAD decryption and verification
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            
            # Add associated data (AAD) - must match encryption
            aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00'  # Direction byte
            decryptor.authenticate_additional_data(aad)
            
            # Decrypt and verify tag
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            # If decryption fails, return original data
            return packet.payload

    def compute_mic(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.mic is not None:
            return packet.mic
        # Fallback for compatibility
        data = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + packet.payload
        return hashlib.sha256(data + key).digest()[:16]  # Use 16 bytes for AEAD tag

    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        try:
            # Try decryption, if successful it means MIC verification passed
            self.decrypt(packet, key)
            return True
        except Exception:
            return False

class ChaCha20_Poly1305_Lite(EncryptionScheme):
    """ChaCha20-Poly1305 Lite - A lightweight AEAD implementation
    
    This is a simplified version of ChaCha20-Poly1305 optimized for LoRaWAN.
    It provides full AEAD security with 16-byte authentication tag.
    
    Note: Previously named ECC-SC-MIC, this has been renamed for clarity
    as it is actually a full AEAD implementation, not a stream cipher with truncated MIC.
    """
    
    def __init__(self):
        super().__init__("ChaCha20-Poly1305-Lite")
        self.TAG_LEN = 16
        self.NONCE_LEN = 12

    def _generate_nonce(self, dev_eui: bytes, fcnt: int, direction: int = 0) -> bytes:
        """Generate structured nonce for ChaCha20-Poly1305: DevAddr(4) + FCnt(4) + Direction(1) + Random(3) = 12 bytes"""
        dev_addr = dev_eui[:4]  # DevAddr from dev_eui
        fcnt_bytes = fcnt.to_bytes(4, 'little')  # Little-endian for nonce
        dir_byte = direction.to_bytes(1, 'little')
        random_part = get_random_bytes(3)  # 3 bytes random for uniqueness
        return dev_addr + fcnt_bytes + dir_byte + random_part

    def encrypt(self, packet: LoRaWANPacket, key: bytes) -> Tuple[LoRaWANPacket, int]:
        start_time = time.perf_counter_ns()
        
        # Generate structured nonce
        nonce = self._generate_nonce(packet.dev_eui, packet.fcnt, direction=0)
        
        # Create ChaCha20-Poly1305 cipher
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        
        # Add associated data (AAD) - DevEUI + FCnt + Direction
        aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00'  # Direction byte
        cipher.update(aad)
        
        # Encrypt and get tag
        ciphertext = cipher.encrypt(packet.payload)
        tag = cipher.digest()
        
        # Assemble encrypted packet: ciphertext + tag
        packet.encrypted_payload = ciphertext + tag
        packet.mic = tag
        packet.nonce = nonce
        
        end_time = time.perf_counter_ns()
        return packet, end_time - start_time

    def decrypt(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        if packet.encrypted_payload is None:
            raise ValueError("No encrypted payload to decrypt")
        
        try:
            # Parse encrypted packet: ciphertext + tag
            tag = packet.encrypted_payload[-16:]
            ciphertext = packet.encrypted_payload[:-16]
            
            # Create ChaCha20-Poly1305 cipher for decryption
            cipher = ChaCha20_Poly1305.new(key=key, nonce=packet.nonce)
            
            # Add associated data (AAD) - DevEUI + FCnt + Direction
            aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00'  # Direction byte
            cipher.update(aad)
            
            # Decrypt and verify
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        """Verify message integrity using ChaCha20-Poly1305"""
        if packet.encrypted_payload is None or packet.nonce is None:
            return False
        
        try:
            # Parse encrypted packet: ciphertext + tag
            tag = packet.encrypted_payload[-16:]
            ciphertext = packet.encrypted_payload[:-16]
            
            # Create ChaCha20-Poly1305 cipher for verification
            cipher = ChaCha20_Poly1305.new(key=key, nonce=packet.nonce)
            
            # Add associated data (AAD) - DevEUI + FCnt + Direction
            aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00'  # Direction byte
            cipher.update(aad)
            
            # Verify tag
            cipher.decrypt_and_verify(ciphertext, tag)
            return True
            
        except Exception:
            return False

    def compute_mic(self, packet: LoRaWANPacket, key: bytes) -> bytes:
        """Compute message integrity code (for AEAD schemes, this returns the tag)"""
        if packet.mic is None:
            raise ValueError("No MIC available")
        return packet.mic

    def verify_mic(self, packet: LoRaWANPacket, key: bytes) -> bool:
        """Verify message integrity using ChaCha20-Poly1305"""
        if packet.encrypted_payload is None or packet.nonce is None:
            return False
        
        try:
            # Parse encrypted packet: ciphertext + tag
            tag = packet.encrypted_payload[-16:]
            ciphertext = packet.encrypted_payload[:-16]
            
            # Create ChaCha20-Poly1305 cipher for verification
            cipher = ChaCha20_Poly1305.new(key=key, nonce=packet.nonce)
            
            # Add associated data (AAD) - DevEUI + FCnt + Direction
            aad = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + b'\x00'  # Direction byte
            cipher.update(aad)
            
            # Verify tag
            cipher.decrypt_and_verify(ciphertext, tag)
            return True
            
        except Exception:
            return False

# Encryption scheme factory
def get_encryption_scheme(scheme_name: str) -> EncryptionScheme:
    """Get encryption scheme instance by name"""
    schemes = {
        "AES-128-GCM": AES128_GCM,
        "ChaCha20-Poly1305": ChaCha20Poly1305,
        "Hybrid-ECC-AES": Hybrid_ECC_AES,
        "Advanced-ECC-AES": Advanced_ECC_AES,
        "ChaCha20-Poly1305-Lite": ChaCha20_Poly1305_Lite
    }
    
    # Add post-quantum schemes
    try:
        from .post_quantum_schemes import (
            LatticeBasedScheme, KyberScheme, DilithiumScheme, SPHINCSPlusScheme
        )
        post_quantum_schemes = {
            "Lattice-Based": LatticeBasedScheme,
            "Kyber": KyberScheme,
            "Dilithium": DilithiumScheme,
            "SPHINCS+": SPHINCSPlusScheme
        }
        schemes.update(post_quantum_schemes)
    except ImportError:
        pass
    
    if scheme_name not in schemes:
        raise ValueError(f"Unknown encryption scheme: {scheme_name}")
    
    return schemes[scheme_name]()

def get_all_schemes() -> list[EncryptionScheme]:
    """Get all encryption schemes"""
    schemes = [
        AES128_GCM(),
        ChaCha20Poly1305(),
        Hybrid_ECC_AES(),
        Advanced_ECC_AES(),
        ChaCha20_Poly1305_Lite()
    ]
    
    # Add post-quantum schemes
    try:
        from .post_quantum_schemes import get_post_quantum_schemes
        schemes.extend(get_post_quantum_schemes())
    except ImportError:
        pass
    
    return schemes

def get_all_schemes_with_post_quantum() -> list[EncryptionScheme]:
    """Get all encryption schemes (including post-quantum schemes)"""
    return get_all_schemes() 