#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LoRa Channel Model

Provides realistic LoRa channel simulation including path loss, shadowing, multipath fading, etc.
"""

import math
import random
import numpy as np
from typing import Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class LoRaSpreadingFactor(Enum):
    """LoRa spreading factor"""
    SF7 = 7
    SF8 = 8
    SF9 = 9
    SF10 = 10
    SF11 = 11
    SF12 = 12


class LoRaBandwidth(Enum):
    """LoRa bandwidth"""
    BW125 = 125000
    BW250 = 250000
    BW500 = 500000


@dataclass
class ChannelParameters:
    """Channel parameters"""
    frequency: float = 868e6  # Hz
    path_loss_exponent: float = 2.7  # Urban environment
    shadowing_std: float = 4.0  # dB
    multipath_enabled: bool = True
    interference_enabled: bool = True
    noise_floor: float = -174  # dBm/Hz


class LoRaChannelModel:
    """LoRa channel model"""
    
    def __init__(self, params: ChannelParameters = None):
        self.params = params or ChannelParameters()
        
        # Multipath fading parameters
        self.multipath_components = 3
        self.delay_spread = 1e-6  # 1μs
        
        # Interference parameters
        self.interference_sources = []
        self.interference_power = -100  # dBm
    
    def calculate_path_loss(self, distance: float) -> float:
        """Calculate path loss"""
        # Free space path loss
        free_space_loss = 20 * math.log10(distance) + 20 * math.log10(self.params.frequency) - 147.55
        
        # Add environmental path loss
        environment_loss = 10 * self.params.path_loss_exponent * math.log10(distance)
        
        # Add shadowing
        shadowing = random.gauss(0, self.params.shadowing_std)
        
        return free_space_loss + environment_loss + shadowing
    
    def calculate_snr(self, tx_power: float, distance: float) -> float:
        """Calculate signal-to-noise ratio"""
        # Calculate path loss
        path_loss = self.calculate_path_loss(distance)
        
        # Received power
        rx_power = tx_power - path_loss
        
        # Noise power
        noise_power = self.params.noise_floor + 10 * math.log10(self.params.frequency / 1e6)
        
        # Signal-to-noise ratio
        snr = rx_power - noise_power
        
        return snr
    
    def calculate_packet_duration(self, payload_size: int, spreading_factor: int, 
                                bandwidth: int) -> float:
        """Calculate packet transmission time"""
        # LoRa symbol time
        symbol_time = (2 ** spreading_factor) / bandwidth
        
        # Preamble symbols
        preamble_symbols = 8
        
        # Payload symbols
        payload_symbols = self._calculate_payload_symbols(payload_size, spreading_factor)
        
        # Total symbols
        total_symbols = preamble_symbols + payload_symbols
        
        # Transmission time
        transmission_time = total_symbols * symbol_time
        
        return transmission_time
    
    def _calculate_payload_symbols(self, payload_size: int, spreading_factor: int) -> int:
        """Calculate payload symbols"""
        # LoRaWAN standard calculation
        n_preamble = 8
        n_payload = payload_size
        
        # Coding rate
        cr = 4/5
        
        # Symbol count calculation
        n_symbols = n_preamble + 8 + math.ceil((8.0 * n_payload - 4.0 * spreading_factor + 28 + 16 - 20) / (4.0 * (spreading_factor - 2))) * cr
        
        return int(n_symbols)
    
    def simulate_multipath_fading(self, signal_power: float) -> float:
        """Simulate multipath fading"""
        if not self.params.multipath_enabled:
            return signal_power
        
        # Rayleigh fading
        fading_gain = np.random.rayleigh(scale=1.0)
        
        # Convert to dB
        fading_db = 20 * math.log10(fading_gain)
        
        return signal_power + fading_db
    
    def simulate_interference(self, signal_power: float) -> float:
        """Simulate interference"""
        if not self.params.interference_enabled:
            return signal_power
        
        # Random interference
        interference_power = self.params.interference_power + random.gauss(0, 5)
        
        # Calculate interference impact
        interference_impact = 10 * math.log10(1 + 10 ** (interference_power / 10))
        
        return signal_power - interference_impact
    
    def calculate_packet_error_rate(self, snr: float, spreading_factor: int) -> float:
        """Calculate packet error rate"""
        # Error rate model based on SNR and spreading factor
        # This is a simplified model, actual implementation should use more complex LoRa error rate model
        
        # Symbol error rate
        symbol_error_rate = 0.5 * math.erfc(math.sqrt(snr / 10))
        
        # Packet error rate (assuming independent errors)
        packet_size = 50  # Assume average packet size
        packet_error_rate = 1 - (1 - symbol_error_rate) ** packet_size
        
        return packet_error_rate
    
    def simulate_packet_transmission(self, tx_power: float, distance: float, 
                                   payload_size: int, spreading_factor: int,
                                   bandwidth: int) -> Tuple[bool, float]:
        """Simulate packet transmission"""
        # Calculate SNR
        snr = self.calculate_snr(tx_power, distance)
        
        # Apply multipath fading
        snr_with_fading = self.simulate_multipath_fading(snr)
        
        # Apply interference
        snr_with_interference = self.simulate_interference(snr_with_fading)
        
        # Calculate error rate
        error_rate = self.calculate_packet_error_rate(snr_with_interference, spreading_factor)
        
        # Determine if transmission is successful
        success = random.random() > error_rate
        
        # Calculate transmission time
        transmission_time = self.calculate_packet_duration(payload_size, spreading_factor, bandwidth)
        
        return success, transmission_time
    
    def calculate_coverage_area(self, tx_power: float, min_snr: float = 6.0) -> float:
        """Calculate coverage area"""
        # Calculate maximum coverage distance based on minimum SNR requirement
        max_distance = 0
        for distance in range(1, 10000, 100):  # 1m to 10km
            snr = self.calculate_snr(tx_power, distance)
            if snr >= min_snr:
                max_distance = distance
            else:
                break
        
        # Calculate coverage area (circular)
        coverage_area = math.pi * max_distance ** 2
        
        return coverage_area


class LoRaInterferenceModel:
    """LoRa interference model"""
    
    def __init__(self):
        self.interference_sources = []
        self.channel_occupancy = 0.3  # 30% channel occupancy
    
    def add_interference_source(self, frequency: float, power: float, 
                              duty_cycle: float = 0.1):
        """Add interference source"""
        self.interference_sources.append({
            'frequency': frequency,
            'power': power,
            'duty_cycle': duty_cycle
        })
    
    def calculate_interference_power(self, frequency: float) -> float:
        """Calculate interference power"""
        total_interference = 0
        
        for source in self.interference_sources:
            # Frequency offset
            freq_offset = abs(frequency - source['frequency'])
            
            # Interference power (attenuates with frequency offset)
            if freq_offset < 125000:  # 125kHz bandwidth
                interference = source['power'] * source['duty_cycle']
                total_interference += interference
        
        return total_interference


class LoRaEnergyModel:
    """LoRa energy consumption model"""
    
    def __init__(self):
        # Energy consumption parameters based on real LoRa devices
        self.cpu_active_power = 25e-3    # 25mW
        self.cpu_sleep_power = 1e-6      # 1μW
        self.radio_tx_power = 14e-3      # 14mW (LoRa)
        self.radio_rx_power = 10.8e-3    # 10.8mW
        self.radio_sleep_power = 0.2e-6  # 0.2μW
        
        # Encryption energy consumption parameters
        self.aes_energy_per_byte = 0.1e-9  # 0.1nJ/byte
        self.ecc_energy_per_operation = 50e-6  # 50μJ/operation
    
    def calculate_encryption_energy(self, encryption_time_ns: int, 
                                  payload_size: int, scheme_name: str) -> float:
        """Calculate encryption energy consumption"""
        # Base CPU energy consumption
        cpu_energy = self.cpu_active_power * (encryption_time_ns / 1e9)
        
        # Adjust energy consumption based on encryption scheme
        if 'AES' in scheme_name:
            scheme_energy = self.aes_energy_per_byte * payload_size
        elif 'ECC' in scheme_name:
            scheme_energy = self.ecc_energy_per_operation
        else:
            scheme_energy = self.aes_energy_per_byte * payload_size
        
        return cpu_energy + scheme_energy
    
    def calculate_transmission_energy(self, transmission_time_s: float, 
                                   spreading_factor: int) -> float:
        """Calculate transmission energy consumption"""
        # Adjust transmission power based on spreading factor
        tx_power = self.radio_tx_power * (2 ** (spreading_factor - 7))
        
        return tx_power * transmission_time_s
    
    def calculate_total_energy(self, encryption_time_ns: int, transmission_time_s: float,
                             payload_size: int, scheme_name: str, 
                             spreading_factor: int) -> float:
        """Calculate total energy consumption"""
        encryption_energy = self.calculate_encryption_energy(encryption_time_ns, payload_size, scheme_name)
        transmission_energy = self.calculate_transmission_energy(transmission_time_s, spreading_factor)
        
        return encryption_energy + transmission_energy 