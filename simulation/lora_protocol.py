#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LoRaWAN Protocol Stack Implementation

Provides LoRaWAN standard-compliant protocol stack functionality.
"""

import time
import random
import hashlib
import struct
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256


class LoRaWANMessageType(Enum):
    """LoRaWAN message types"""
    JOIN_REQUEST = 0x00
    JOIN_ACCEPT = 0x01
    UNCONFIRMED_DATA_UP = 0x40
    UNCONFIRMED_DATA_DOWN = 0x60
    CONFIRMED_DATA_UP = 0x80
    CONFIRMED_DATA_DOWN = 0xA0
    REJOIN_REQUEST = 0xC0


@dataclass
class LoRaWANJoinRequest:
    """LoRaWAN Join Request message"""
    join_eui: bytes  # 8 bytes
    dev_eui: bytes   # 8 bytes
    dev_nonce: bytes # 2 bytes
    
    def to_bytes(self) -> bytes:
        """Convert to byte sequence"""
        return self.join_eui + self.dev_eui + self.dev_nonce


@dataclass
class LoRaWANDataMessage:
    """LoRaWAN data message"""
    mhdr: bytes      # 1 byte
    dev_addr: bytes  # 4 bytes
    f_ctrl: bytes    # 1 byte
    f_cnt: bytes     # 2 bytes
    f_port: bytes    # 1 byte
    frm_payload: bytes  # N bytes
    f_mic: bytes     # 4 bytes
    
    def to_bytes(self) -> bytes:
        """Convert to byte sequence"""
        return (self.mhdr + self.dev_addr + self.f_ctrl + 
                self.f_cnt + self.f_port + self.frm_payload + self.f_mic)


class LoRaWANProtocol:
    """LoRaWAN protocol stack"""
    
    def __init__(self):
        # Device identifiers
        self.join_eui = get_random_bytes(8)
        self.dev_eui = get_random_bytes(8)
        self.dev_addr = get_random_bytes(4)
        
        # Keys
        self.app_key = get_random_bytes(16)
        self.nwk_key = get_random_bytes(16)
        self.app_s_key = get_random_bytes(16)
        self.f_nwk_s_int_key = get_random_bytes(16)
        self.s_nwk_s_int_key = get_random_bytes(16)
        self.nwk_s_enc_key = get_random_bytes(16)
        
        # Counters
        self.fcnt_up = 0
        self.fcnt_down = 0
        
        # Session state
        self.is_joined = False
        self.dev_nonce = 0
    
    def generate_join_request(self) -> LoRaWANJoinRequest:
        """Generate Join Request message"""
        self.dev_nonce = random.randint(0, 65535)
        
        return LoRaWANJoinRequest(
            join_eui=self.join_eui,
            dev_eui=self.dev_eui,
            dev_nonce=self.dev_nonce.to_bytes(2, 'little')
        )
    
    def process_join_accept(self, join_accept_data: bytes) -> bool:
        """Process Join Accept message"""
        try:
            # Decrypt Join Accept
            decrypted = self._decrypt_join_accept(join_accept_data)
            
            # Parse Join Accept
            if len(decrypted) >= 17:
                # Extract AppNonce, NetID, DevAddr, DLsettings, RxDelay, CFList
                app_nonce = decrypted[0:3]
                net_id = decrypted[3:6]
                dev_addr = decrypted[6:10]
                dl_settings = decrypted[10:11]
                rx_delay = decrypted[11:12]
                cf_list = decrypted[12:17]
                
                # Update device address
                self.dev_addr = dev_addr
                
                # Derive session keys
                self._derive_session_keys(app_nonce, net_id, self.dev_nonce)
                
                # Mark as joined
                self.is_joined = True
                self.fcnt_up = 0
                self.fcnt_down = 0
                
                return True
        except Exception:
            pass
        
        return False
    
    def generate_data_message(self, payload: bytes, f_port: int = 1, 
                            confirmed: bool = False) -> LoRaWANDataMessage:
        """Generate data message"""
        if not self.is_joined:
            raise ValueError("Device not joined to network")
        
        # Message header
        if confirmed:
            mhdr = bytes([LoRaWANMessageType.CONFIRMED_DATA_UP.value])
        else:
            mhdr = bytes([LoRaWANMessageType.UNCONFIRMED_DATA_UP.value])
        
        # Frame control
        f_ctrl = bytes([0x00])  # No ADR, no ACK, no FPending
        
        # Frame counter
        f_cnt = self.fcnt_up.to_bytes(2, 'little')
        self.fcnt_up += 1
        
        # Port
        f_port = bytes([f_port])
        
        # Encrypt payload
        encrypted_payload = self._encrypt_payload(payload, f_port)
        
        # Calculate MIC
        f_mic = self._calculate_mic(mhdr, f_ctrl, f_cnt, f_port, encrypted_payload)
        
        return LoRaWANDataMessage(
            mhdr=mhdr,
            dev_addr=self.dev_addr,
            f_ctrl=f_ctrl,
            f_cnt=f_cnt,
            f_port=f_port,
            frm_payload=encrypted_payload,
            f_mic=f_mic
        )
    
    def _derive_session_keys(self, app_nonce: bytes, net_id: bytes, dev_nonce: int):
        """Derive session keys"""
        # Calculate AppSKey
        app_key_derivation = b'\x02' + self.app_key + app_nonce + net_id + dev_nonce.to_bytes(2, 'little')
        self.app_s_key = hashlib.sha256(app_key_derivation).digest()[:16]
        
        # Calculate NwkSKey
        nwk_key_derivation = b'\x01' + self.nwk_key + app_nonce + net_id + dev_nonce.to_bytes(2, 'little')
        self.f_nwk_s_int_key = hashlib.sha256(nwk_key_derivation).digest()[:16]
        self.s_nwk_s_int_key = self.f_nwk_s_int_key
        self.nwk_s_enc_key = self.f_nwk_s_int_key
    
    def _encrypt_payload(self, payload: bytes, f_port: int) -> bytes:
        """Encrypt payload"""
        if f_port == 0:
            # Use NwkSKey for encryption
            key = self.f_nwk_s_int_key
        else:
            # Use AppSKey for encryption
            key = self.app_s_key
        
        # Generate nonce
        nonce = self._generate_payload_nonce(f_port)
        
        # AES encryption
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.encrypt(payload)
    
    def _generate_payload_nonce(self, f_port: int) -> bytes:
        """Generate payload nonce"""
        # LoRaWAN standard: DevAddr(4) + FCntUp(4) + 0x000000(4)
        dev_addr = self.dev_addr
        fcnt = self.fcnt_up.to_bytes(4, 'little')
        padding = b'\x00\x00\x00\x00'
        return dev_addr + fcnt + padding
    
    def _calculate_mic(self, mhdr: bytes, f_ctrl: bytes, f_cnt: bytes, 
                      f_port: bytes, frm_payload: bytes) -> bytes:
        """Calculate MIC"""
        # Build MIC input
        mic_input = mhdr + self.dev_addr + f_ctrl + f_cnt + f_port + frm_payload
        
        # Calculate MIC using NwkSKey
        cipher = AES.new(self.f_nwk_s_int_key, AES.MODE_ECB)
        mic = cipher.encrypt(mic_input + b'\x00' * 16)[:4]
        
        return mic
    
    def _decrypt_join_accept(self, join_accept_data: bytes) -> bytes:
        """Decrypt Join Accept"""
        # Use AppKey for decryption
        cipher = AES.new(self.app_key, AES.MODE_ECB)
        decrypted = cipher.decrypt(join_accept_data)
        return decrypted


class LoRaWANNetwork:
    """LoRaWAN network simulation"""
    
    def __init__(self):
        self.devices: Dict[bytes, LoRaWANProtocol] = {}
        self.join_requests: List[Tuple[bytes, LoRaWANJoinRequest]] = []
        self.data_messages: List[Tuple[bytes, LoRaWANDataMessage]] = []
    
    def register_device(self, dev_eui: bytes) -> LoRaWANProtocol:
        """Register device"""
        device = LoRaWANProtocol()
        device.dev_eui = dev_eui
        self.devices[dev_eui] = device
        return device
    
    def process_join_request(self, dev_eui: bytes, join_request: LoRaWANJoinRequest) -> bool:
        """Process Join Request"""
        if dev_eui in self.devices:
            # Simulate network server accepting Join Request
            # Generate Join Accept
            join_accept = self._generate_join_accept(join_request)
            
            # Process Join Accept
            device = self.devices[dev_eui]
            success = device.process_join_accept(join_accept)
            
            if success:
                self.join_requests.append((dev_eui, join_request))
            
            return success
        
        return False
    
    def process_data_message(self, dev_eui: bytes, data_message: LoRaWANDataMessage) -> bool:
        """Process data message"""
        if dev_eui in self.devices:
            device = self.devices[dev_eui]
            if device.is_joined:
                self.data_messages.append((dev_eui, data_message))
                return True
        
        return False
    
    def _generate_join_accept(self, join_request: LoRaWANJoinRequest) -> bytes:
        """Generate Join Accept message"""
        # Simulate Join Accept data
        app_nonce = get_random_bytes(3)
        net_id = get_random_bytes(3)
        dev_addr = get_random_bytes(4)
        dl_settings = bytes([0x00])  # Default settings
        rx_delay = bytes([0x01])     # 1 second delay
        cf_list = get_random_bytes(5) # Channel list
        
        # Build Join Accept
        join_accept_data = app_nonce + net_id + dev_addr + dl_settings + rx_delay + cf_list
        
        # Encrypt Join Accept
        cipher = AES.new(self.devices[join_request.dev_eui].app_key, AES.MODE_ECB)
        encrypted = cipher.encrypt(join_accept_data + b'\x00' * 16)
        
        return encrypted 