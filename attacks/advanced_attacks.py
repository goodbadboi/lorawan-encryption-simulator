#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Attack Types Module

Provides more realistic attack types, including power analysis, fault injection, etc.
"""

import time
import random
import hashlib
import struct
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

from .attack_types import BaseAttack, AttackType, AttackResult
from encryption.schemes import LoRaWANPacket, get_encryption_scheme


class PowerAnalysisAttack(BaseAttack):
    """Power analysis attack (simulation)"""
    
    def __init__(self):
        super().__init__("Power Analysis Attack", AttackType.POWER_ANALYSIS)
        self.power_traces = {}
    
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> AttackResult:
        start_time = time.perf_counter_ns()
        attempts = 0
        
        # Simulate power analysis
        # In real attacks, this requires actual power measurement equipment
        
        # Generate simulated power trace
        power_trace = self._generate_power_trace(packet, scheme_name, key)
        
        # Analyze power patterns
        correlation = self._analyze_power_correlation(power_trace, key)
        
        attempts += 1
        
        # If correlation is high enough, consider attack successful
        if correlation > 0.8:
            end_time = time.perf_counter_ns()
            return AttackResult(
                attack_type=self.attack_type,
                target_scheme=scheme_name,
                success=True,
                attack_time_ns=end_time - start_time,
                attempts=attempts,
                details={
                    "correlation": correlation,
                    "power_trace_length": len(power_trace),
                    "attack_type": "DPA"
                },
                vulnerability_score=self._calculate_vulnerability_score(True, attempts, end_time - start_time)
            )
        
        end_time = time.perf_counter_ns()
        return AttackResult(
            attack_type=self.attack_type,
            target_scheme=scheme_name,
            success=False,
            attack_time_ns=end_time - start_time,
            attempts=attempts,
            details={
                "correlation": correlation,
                "power_trace_length": len(power_trace),
                "attack_type": "DPA"
            },
            vulnerability_score=0.0
        )
    
    def _generate_power_trace(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> List[float]:
        """Generate simulated power trace"""
        # Simulate power consumption changes during encryption
        trace_length = 1000 + random.randint(0, 500)
        power_trace = []
        
        # Simulate power consumption in different stages
        for i in range(trace_length):
            if i < 100:  # Initialization stage
                power = random.uniform(0.1, 0.3)
            elif i < 300:  # Key scheduling stage
                power = random.uniform(0.5, 0.8)
            elif i < 700:  # Encryption stage
                power = random.uniform(0.6, 1.0)
            else:  # Completion stage
                power = random.uniform(0.2, 0.4)
            
            # Add noise
            power += random.uniform(-0.1, 0.1)
            power_trace.append(max(0, power))
        
        return power_trace
    
    def _analyze_power_correlation(self, power_trace: List[float], key: bytes) -> float:
        """Analyze power correlation"""
        # Simulate correlation analysis
        # In real attacks, this requires complex statistical analysis
        
        # Calculate theoretical power based on key bytes
        theoretical_power = []
        for byte in key:
            # Simulate Hamming weight (number of 1s)
            hamming_weight = bin(byte).count('1')
            theoretical_power.append(hamming_weight / 8.0)
        
        # Calculate correlation (simplified implementation)
        if len(power_trace) >= len(theoretical_power):
            correlation = sum(p * t for p, t in zip(power_trace[:len(theoretical_power)], theoretical_power))
            correlation /= len(theoretical_power)
            return min(1.0, max(0.0, correlation))
        
        return random.uniform(0.1, 0.6)


class FaultInjectionAttack(BaseAttack):
    """Fault injection attack (simulation)"""
    
    def __init__(self):
        super().__init__("Fault Injection Attack", AttackType.FAULT_INJECTION)
        self.fault_types = ['bit_flip', 'byte_corruption', 'timing_fault']
    
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> AttackResult:
        start_time = time.perf_counter_ns()
        attempts = 0
        
        scheme = get_encryption_scheme(scheme_name)
        
        # Try different types of fault injection
        for fault_type in self.fault_types:
            attempts += 1
            
            # Create faulty packet
            faulty_packet = self._inject_fault(packet, fault_type)
            
            # Try to decrypt faulty packet
            try:
                decrypted = scheme.decrypt(faulty_packet, key)
                
                # Check if useful information was obtained
                if self._analyze_fault_result(decrypted, packet.payload):
                    end_time = time.perf_counter_ns()
                    return AttackResult(
                        attack_type=self.attack_type,
                        target_scheme=scheme_name,
                        success=True,
                        attack_time_ns=end_time - start_time,
                        attempts=attempts,
                        details={
                            "fault_type": fault_type,
                            "fault_location": "encrypted_payload",
                            "attack_method": "Differential Fault Analysis"
                        },
                        vulnerability_score=self._calculate_vulnerability_score(True, attempts, end_time - start_time)
                    )
            except Exception:
                continue
        
        end_time = time.perf_counter_ns()
        return AttackResult(
            attack_type=self.attack_type,
            target_scheme=scheme_name,
            success=False,
            attack_time_ns=end_time - start_time,
            attempts=attempts,
            details={
                "fault_types_tried": self.fault_types,
                "attack_method": "Differential Fault Analysis"
            },
            vulnerability_score=0.0
        )
    
    def _inject_fault(self, packet: LoRaWANPacket, fault_type: str) -> LoRaWANPacket:
        """Inject fault"""
        faulty_packet = LoRaWANPacket(
            dev_eui=packet.dev_eui,
            payload=packet.payload,
            fcnt=packet.fcnt
        )
        
        if packet.encrypted_payload:
            faulty_payload = bytearray(packet.encrypted_payload)
            
            if fault_type == 'bit_flip':
                # Randomly flip one bit
                if faulty_payload:
                    byte_pos = random.randint(0, len(faulty_payload) - 1)
                    bit_pos = random.randint(0, 7)
                    faulty_payload[byte_pos] ^= (1 << bit_pos)
            
            elif fault_type == 'byte_corruption':
                # Randomly corrupt one byte
                if faulty_payload:
                    pos = random.randint(0, len(faulty_payload) - 1)
                    faulty_payload[pos] = random.randint(0, 255)
            
            elif fault_type == 'timing_fault':
                # Simulate timing fault (by modifying nonce)
                if hasattr(packet, 'nonce') and packet.nonce:
                    faulty_nonce = bytearray(packet.nonce)
                    if faulty_nonce:
                        pos = random.randint(0, len(faulty_nonce) - 1)
                        faulty_nonce[pos] = random.randint(0, 255)
                    faulty_packet.nonce = bytes(faulty_nonce)
            
            faulty_packet.encrypted_payload = bytes(faulty_payload)
        
        # Copy other attributes
        if hasattr(packet, 'mic') and packet.mic:
            faulty_packet.mic = packet.mic
        if hasattr(packet, 'nonce') and packet.nonce and not hasattr(faulty_packet, 'nonce'):
            faulty_packet.nonce = packet.nonce
        
        return faulty_packet
    
    def _analyze_fault_result(self, decrypted: bytes, original: bytes) -> bool:
        """Analyze fault injection results"""
        # Check if decryption result contains useful information
        if len(decrypted) != len(original):
            return True  # Different length may leak information
        
        # Check if there is partially correct information
        correct_bytes = sum(1 for a, b in zip(decrypted, original) if a == b)
        if correct_bytes > len(original) * 0.8:
            return True  # Mostly correct may leak information
        
        return False


class AdvancedReplayAttack(BaseAttack):
    """Enhanced replay attack (considering time windows)"""
    
    def __init__(self):
        super().__init__("Enhanced Replay Attack", AttackType.ADVANCED_REPLAY)
        self.captured_packets = {}
        self.time_windows = {}  # Time window for each device
    
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> AttackResult:
        start_time = time.perf_counter_ns()
        attempts = 0
        
        device_id = packet.dev_eui.hex()
        current_time = time.time()
        
        # Initialize device time window
        if device_id not in self.time_windows:
            self.time_windows[device_id] = {
                'last_fcnt': 0,
                'last_time': current_time,
                'window_size': 100  # Time window size
            }
        
        # Check time window
        window = self.time_windows[device_id]
        time_diff = current_time - window['last_time']
        
        # If time window has expired, reset
        if time_diff > 300:  # 5-minute window
            window['last_fcnt'] = 0
            window['last_time'] = current_time
        
        # Try replay attack
        if device_id in self.captured_packets:
            for captured_packet in self.captured_packets[device_id]:
                attempts += 1
                
                # Check if FCnt is within allowed range
                if (captured_packet.fcnt > window['last_fcnt'] and 
                    captured_packet.fcnt <= window['last_fcnt'] + window['window_size']):
                    
                    # Try replay
                    if self._try_replay(captured_packet, scheme_name, key):
                        end_time = time.perf_counter_ns()
                        return AttackResult(
                            attack_type=self.attack_type,
                            target_scheme=scheme_name,
                            success=True,
                            attack_time_ns=end_time - start_time,
                            attempts=attempts,
                            details={
                                "replayed_fcnt": captured_packet.fcnt,
                                "time_window": time_diff,
                                "attack_method": "Time Window Replay"
                            },
                            vulnerability_score=self._calculate_vulnerability_score(True, attempts, end_time - start_time)
                        )
        
        # Capture current packet
        if device_id not in self.captured_packets:
            self.captured_packets[device_id] = []
        self.captured_packets[device_id].append(packet)
        
        # Update time window
        window['last_fcnt'] = max(window['last_fcnt'], packet.fcnt)
        window['last_time'] = current_time
        
        end_time = time.perf_counter_ns()
        return AttackResult(
            attack_type=self.attack_type,
            target_scheme=scheme_name,
            success=False,
            attack_time_ns=end_time - start_time,
            attempts=attempts,
            details={
                "time_window": time_diff,
                "attack_method": "Time Window Replay"
            },
            vulnerability_score=0.0
        )
    
    def _try_replay(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> bool:
        """Try to replay packet"""
        try:
            scheme = get_encryption_scheme(scheme_name)
            # Verify MIC
            if scheme.verify_mic(packet, key):
                return True
        except Exception:
            pass
        return False


class RainbowTableAttack(BaseAttack):
    """Rainbow table attack (precomputed attack)"""
    
    def __init__(self):
        super().__init__("Rainbow Table Attack", AttackType.RAINBOW_TABLE)
        self.rainbow_table = {}
        self._build_rainbow_table()
    
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> AttackResult:
        start_time = time.perf_counter_ns()
        attempts = 0
        
        # Calculate packet hash value
        packet_hash = self._compute_packet_hash(packet)
        
        # Look up in rainbow table
        if packet_hash in self.rainbow_table:
            attempts += 1
            end_time = time.perf_counter_ns()
            return AttackResult(
                attack_type=self.attack_type,
                target_scheme=scheme_name,
                success=True,
                attack_time_ns=end_time - start_time,
                attempts=attempts,
                details={
                    "rainbow_table_size": len(self.rainbow_table),
                    "found_key": self.rainbow_table[packet_hash].hex(),
                    "attack_method": "Precomputed Table"
                },
                vulnerability_score=self._calculate_vulnerability_score(True, attempts, end_time - start_time)
            )
        
        end_time = time.perf_counter_ns()
        return AttackResult(
            attack_type=self.attack_type,
            target_scheme=scheme_name,
            success=False,
            attack_time_ns=end_time - start_time,
            attempts=attempts,
            details={
                "rainbow_table_size": len(self.rainbow_table),
                "attack_method": "Precomputed Table"
            },
            vulnerability_score=0.0
        )
    
    def _build_rainbow_table(self):
        """Build rainbow table"""
        print("🔧 Building rainbow table...")
        
        # Generate common keys and corresponding hash values
        common_keys = [
            b'\x00' * 16,
            b'\xFF' * 16,
            b'password123456',
            b'admin123456789',
            b'1234567890123456',
            b'abcdefghijklmnop',
            b'qwertyuiopasdfgh',
            b'zxcvbnm123456789',
        ]
        
        for key in common_keys:
            # Create test packet
            test_packet = LoRaWANPacket(
                dev_eui=b'TEST_DEVICE',
                payload=b'TEST_PAYLOAD',
                fcnt=1
            )
            
            # Calculate hash value
            packet_hash = self._compute_packet_hash(test_packet)
            self.rainbow_table[packet_hash] = key
        
        print(f"✅ Rainbow table construction completed, containing {len(self.rainbow_table)} entries")
    
    def _compute_packet_hash(self, packet: LoRaWANPacket) -> str:
        """Calculate packet hash value"""
        data = packet.dev_eui + packet.fcnt.to_bytes(4, 'big') + packet.payload
        return hashlib.sha256(data).hexdigest()[:16]


# Update attack type enumeration
class AdvancedAttackType:
    """Advanced attack types"""
    POWER_ANALYSIS = "power_analysis"
    FAULT_INJECTION = "fault_injection"
    ADVANCED_REPLAY = "advanced_replay"
    RAINBOW_TABLE = "rainbow_table"


def get_advanced_attacks():
    """Get all advanced attack types"""
    return [
        PowerAnalysisAttack(),
        FaultInjectionAttack(),
        AdvancedReplayAttack(),
        RainbowTableAttack()
    ]
