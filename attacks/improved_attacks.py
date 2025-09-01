#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Improved Attack Implementation

Provides more realistic attack simulation including real brute force, signal interference, etc.
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

from encryption.schemes import LoRaWANPacket, get_encryption_scheme


class ImprovedBruteForceAttack:
    """Improved brute force attack"""
    
    def __init__(self):
        self.name = "Improved Brute Force Attack"
        self.max_attempts = 1000  # Reduce attempts to avoid hanging
        
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> Dict[str, Any]:
        """Execute real brute force attack"""
        start_time = time.perf_counter_ns()
        attempts = 0
        timeout = 5.0  # 5 second timeout
        
        # 1. Try common weak keys
        weak_keys = [
            b'\x00' * 16,  # All zero key
            b'\xFF' * 16,  # All one key
            b'password123456',  # Weak password
            b'admin123456789',  # Admin password
            b'1234567890123456',  # Numeric key
            b'abcdefghijklmnop',  # Alphabetic key
        ]
        
        # 2. Try keys based on target information
        if hasattr(packet, 'dev_eui'):
            dev_eui_based_keys = [
                packet.dev_eui + b'\x00' * 8,
                packet.dev_eui[:8] + packet.dev_eui[:8],
                hashlib.md5(packet.dev_eui).digest(),
            ]
            weak_keys.extend(dev_eui_based_keys)
        
        # 3. Try keys based on frame counter
        if hasattr(packet, 'fcnt'):
            fcnt_based_keys = [
                packet.fcnt.to_bytes(16, 'big'),
                packet.fcnt.to_bytes(16, 'little'),
                hashlib.md5(packet.fcnt.to_bytes(4, 'big')).digest(),
            ]
            weak_keys.extend(fcnt_based_keys)
        
        # 4. Try random keys
        for i in range(self.max_attempts - len(weak_keys)):
            weak_keys.append(get_random_bytes(16))
        
        # 5. Execute brute force
        for test_key in weak_keys:
            attempts += 1
            
            # Check timeout
            if (time.perf_counter_ns() - start_time) / 1e9 > timeout:
                break
            
            try:
                scheme = get_encryption_scheme(scheme_name)
                decrypted = scheme.decrypt(packet, test_key)
                
                # Check if decryption result is meaningful
                if self._is_valid_decryption(decrypted):
                    end_time = time.perf_counter_ns()
                    return {
                        'success': True,
                        'attempts': attempts,
                        'time_ns': end_time - start_time,
                        'found_key': test_key.hex(),
                        'decrypted_length': len(decrypted),
                        'attack_type': 'brute_force_improved'
                    }
            except Exception:
                continue
        
        end_time = time.perf_counter_ns()
        return {
            'success': False,
            'attempts': attempts,
            'time_ns': end_time - start_time,
            'attack_type': 'brute_force_improved'
        }
    
    def _is_valid_decryption(self, decrypted: bytes) -> bool:
        """Check if decryption result is valid"""
        if len(decrypted) == 0:
            return False
        
        # Check if all zeros
        if all(b == 0 for b in decrypted):
            return False
        
        # Check if contains printable characters
        printable_count = sum(1 for b in decrypted if 32 <= b <= 126)
        if printable_count / len(decrypted) > 0.7:
            return True
        
        # Check if has repeating patterns
        if len(decrypted) >= 8:
            pattern = decrypted[:4]
            if decrypted.count(pattern) > len(decrypted) / 8:
                return True
        
        return False


class ImprovedJammingAttack:
    """Improved jamming attack"""
    
    def __init__(self):
        self.name = "Improved Jamming Attack"
        
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> Dict[str, Any]:
        """Execute real signal jamming attack"""
        start_time = time.perf_counter_ns()
        attempts = 0
        
        # 1. Simulate different jamming types
        jamming_types = [
            'narrowband_jamming',    # Narrowband jamming
            'wideband_jamming',      # Wideband jamming
            'pulse_jamming',         # Pulse jamming
            'frequency_hopping_jamming',  # Frequency hopping jamming
            'selective_jamming'      # Selective jamming
        ]
        
        for jamming_type in jamming_types:
            attempts += 1
            
            # 2. Modify packet according to jamming type
            corrupted_packet = self._apply_jamming(packet, jamming_type)
            
            try:
                scheme = get_encryption_scheme(scheme_name)
                decrypted = scheme.decrypt(corrupted_packet, key)
                
                # 3. Check if successfully bypassed error detection
                if len(decrypted) > 0:
                    end_time = time.perf_counter_ns()
                    return {
                        'success': True,
                        'attempts': attempts,
                        'time_ns': end_time - start_time,
                        'jamming_type': jamming_type,
                        'decrypted_length': len(decrypted),
                        'attack_type': 'jamming_improved'
                    }
            except Exception:
                continue
        
        end_time = time.perf_counter_ns()
        return {
            'success': False,
            'attempts': attempts,
            'time_ns': end_time - start_time,
            'attack_type': 'jamming_improved'
        }
    
    def _apply_jamming(self, packet: LoRaWANPacket, jamming_type: str) -> LoRaWANPacket:
        """Apply different types of jamming"""
        corrupted_packet = LoRaWANPacket(
            dev_eui=packet.dev_eui,
            payload=packet.payload,
            fcnt=packet.fcnt
        )
        
        if packet.encrypted_payload:
            if jamming_type == 'narrowband_jamming':
                # Narrowband jamming: only modify specific bytes
                payload = bytearray(packet.encrypted_payload)
                for i in range(0, len(payload), 8):
                    if i < len(payload):
                        payload[i] ^= 0xFF
                corrupted_packet.encrypted_payload = bytes(payload)
                
            elif jamming_type == 'wideband_jamming':
                # Wideband jamming: randomly modify multiple bytes
                payload = bytearray(packet.encrypted_payload)
                for i in range(len(payload)):
                    if random.random() < 0.3:  # 30% probability of modification
                        payload[i] ^= random.randint(1, 255)
                corrupted_packet.encrypted_payload = bytes(payload)
                
            elif jamming_type == 'pulse_jamming':
                # Pulse jamming: periodic modification
                payload = bytearray(packet.encrypted_payload)
                for i in range(0, len(payload), 4):
                    if i < len(payload):
                        payload[i:i+2] = b'\x00\x00'
                corrupted_packet.encrypted_payload = bytes(payload)
                
            elif jamming_type == 'frequency_hopping_jamming':
                # Frequency hopping jamming: modify at different positions
                payload = bytearray(packet.encrypted_payload)
                positions = random.sample(range(len(payload)), min(5, len(payload)))
                for pos in positions:
                    payload[pos] = random.randint(0, 255)
                corrupted_packet.encrypted_payload = bytes(payload)
                
            elif jamming_type == 'selective_jamming':
                # Selective jamming: modify key fields
                payload = bytearray(packet.encrypted_payload)
                if len(payload) >= 16:
                    # Modify first 16 bytes (may contain nonce or IV)
                    payload[:16] = get_random_bytes(16)
                corrupted_packet.encrypted_payload = bytes(payload)
        
        return corrupted_packet


class ImprovedKeyExtractionAttack:
    """Improved key extraction attack"""
    
    def __init__(self):
        self.name = "Improved Key Extraction Attack"
        
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> Dict[str, Any]:
        """Execute more realistic key extraction attack"""
        start_time = time.perf_counter_ns()
        attempts = 0
        
        extraction_methods = [
            self._analyze_entropy_pattern,
            self._analyze_correlation_pattern,
            self._analyze_frequency_pattern,
            self._analyze_linear_pattern,
            self._analyze_differential_pattern
        ]
        
        for method in extraction_methods:
            attempts += 1
            
            try:
                extracted_info = method(packet)
                
                if extracted_info and len(extracted_info) > 0:
                    end_time = time.perf_counter_ns()
                    return {
                        'success': True,
                        'attempts': attempts,
                        'time_ns': end_time - start_time,
                        'extraction_method': method.__name__,
                        'extracted_info_length': len(extracted_info),
                        'attack_type': 'key_extraction_improved'
                    }
            except Exception:
                continue
        
        end_time = time.perf_counter_ns()
        return {
            'success': False,
            'attempts': attempts,
            'time_ns': end_time - start_time,
            'attack_type': 'key_extraction_improved'
        }
    
    def _analyze_entropy_pattern(self, packet: LoRaWANPacket) -> Optional[bytes]:
        """Analyze entropy patterns"""
        if not packet.encrypted_payload:
            return None
        
        # Calculate byte entropy
        byte_counts = [0] * 256
        for byte in packet.encrypted_payload:
            byte_counts[byte] += 1
        
        # Calculate information entropy
        total_bytes = len(packet.encrypted_payload)
        entropy = 0
        for count in byte_counts:
            if count > 0:
                p = count / total_bytes
                entropy -= p * (p.bit_length() - 1)
        
        # If entropy is too low, patterns may exist
        if entropy < 7.0:  # Ideal entropy is about 8.0
            return packet.encrypted_payload[:16]
        
        return None
    
    def _analyze_correlation_pattern(self, packet: LoRaWANPacket) -> Optional[bytes]:
        """Analyze correlation patterns"""
        if not packet.encrypted_payload or len(packet.encrypted_payload) < 32:
            return None
        
        payload = packet.encrypted_payload
        
        # Calculate autocorrelation
        correlations = []
        for lag in range(1, min(16, len(payload))):
            correlation = 0
            for i in range(len(payload) - lag):
                correlation += payload[i] * payload[i + lag]
            correlations.append(correlation)
        
        # If strong correlation exists, may leak key information
        max_correlation = max(correlations)
        if max_correlation > 1000:  # Threshold
            return payload[:16]
        
        return None
    
    def _analyze_frequency_pattern(self, packet: LoRaWANPacket) -> Optional[bytes]:
        """Analyze frequency patterns"""
        if not packet.encrypted_payload:
            return None
        
        # Calculate byte frequency distribution
        byte_freq = {}
        for byte in packet.encrypted_payload:
            byte_freq[byte] = byte_freq.get(byte, 0) + 1
        
        # Check for abnormal frequencies
        total_bytes = len(packet.encrypted_payload)
        expected_freq = total_bytes / 256
        
        abnormal_count = 0
        for freq in byte_freq.values():
            if abs(freq - expected_freq) > expected_freq * 0.5:
                abnormal_count += 1
        
        # If too many abnormal frequencies, patterns may exist
        if abnormal_count > 50:
            return packet.encrypted_payload[:16]
        
        return None
    
    def _analyze_linear_pattern(self, packet: LoRaWANPacket) -> Optional[bytes]:
        """Analyze linear patterns"""
        if not packet.encrypted_payload or len(packet.encrypted_payload) < 16:
            return None
        
        payload = packet.encrypted_payload
        
        # Check linear relationships
        for i in range(len(payload) - 3):
            # Check if linear relationship exists: y = ax + b
            x1, x2 = payload[i], payload[i+1]
            y1, y2 = payload[i+2], payload[i+3]
            
            if x2 != x1:
                a = (y2 - y1) / (x2 - x1)
                b = y1 - a * x1
                
                # Check if subsequent bytes satisfy linear relationship
                matches = 0
                for j in range(i+4, min(i+20, len(payload))):
                    expected = int(a * payload[j-2] + b) % 256
                    if payload[j] == expected:
                        matches += 1
                
                if matches > 5:  # If more than 5 bytes satisfy linear relationship
                    return payload[i:i+16]
        
        return None
    
    def _analyze_differential_pattern(self, packet: LoRaWANPacket) -> Optional[bytes]:
        """Analyze differential patterns"""
        if not packet.encrypted_payload or len(packet.encrypted_payload) < 16:
            return None
        
        payload = packet.encrypted_payload
        
        # Calculate differences
        diffs = []
        for i in range(len(payload) - 1):
            diffs.append(payload[i+1] - payload[i])
        
        # Check differential patterns
        diff_counts = {}
        for diff in diffs:
            diff_counts[diff] = diff_counts.get(diff, 0) + 1
        
        # If a differential value appears too frequently, patterns may exist
        max_diff_count = max(diff_counts.values())
        if max_diff_count > len(diffs) * 0.3:  # Over 30%
            return payload[:16]
        
        return None


def test_improved_attacks():
    """Test improved attacks"""
    print("🧪 Testing improved attack implementation...")
    
    # Create test packet
    test_packet = LoRaWANPacket(
        dev_eui=b'DEVICE001',
        payload=b'TEST_PAYLOAD_DATA',
        fcnt=123
    )
    
    # Test improved brute force attack
    print("\n🔍 Testing improved brute force attack...")
    brute_force = ImprovedBruteForceAttack()
    result = brute_force.execute(test_packet, "AES-128-GCM", b'TEST_KEY_16BYTES')
    print(f"   Result: {result}")
    
    # Test improved jamming attack
    print("\n🔍 Testing improved jamming attack...")
    jamming = ImprovedJammingAttack()
    result = jamming.execute(test_packet, "ChaCha20-Poly1305", b'TEST_KEY_32BYTES')
    print(f"   Result: {result}")
    
    # Test improved key extraction attack
    print("\n🔍 Testing improved key extraction attack...")
    key_extraction = ImprovedKeyExtractionAttack()
    result = key_extraction.execute(test_packet, "Hybrid-ECC-AES", b'TEST_KEY_16BYTES')
    print(f"   Result: {result}")
    
    print("\n✅ Improved attack testing completed")


if __name__ == "__main__":
    test_improved_attacks() 