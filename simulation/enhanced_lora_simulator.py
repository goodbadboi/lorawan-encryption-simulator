#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced LoRaWAN Simulator

Provides more realistic LoRaWAN network simulation including:
- Complete LoRaWAN protocol stack
- Realistic channel model
- ADR mechanism
- Device type support
- Key management
"""

import os
import csv
import json
import random
import numpy as np
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Any, Set
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import math

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from encryption.schemes import LoRaWANPacket, get_encryption_scheme, EncryptionScheme

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

class DeviceClass(Enum):
    """LoRaWAN device types"""
    CLASS_A = "A"  # Bidirectional communication, downlink windows
    CLASS_B = "B"  # Bidirectional communication, periodic downlink
    CLASS_C = "C"  # Bidirectional communication, continuous downlink

@dataclass
class LoRaWANKeys:
    """LoRaWAN keys"""
    app_key: bytes
    nwk_key: bytes
    app_session_key: bytes
    nwk_session_key: bytes
    fcnt_up: int = 0
    fcnt_down: int = 0

@dataclass
class EnhancedLoRaDevice:
    """Enhanced LoRa device model"""
    device_id: str
    location: Tuple[float, float]
    device_class: DeviceClass
    spreading_factor: LoRaSpreadingFactor
    bandwidth: LoRaBandwidth
    transmission_power: float
    encryption_scheme: str
    packet_size: int
    transmission_interval: float
    dev_eui: Optional[bytes] = None
    app_eui: Optional[bytes] = None
    keys: Optional[LoRaWANKeys] = None
    adr_enabled: bool = True
    battery_level: float = 100.0
    temperature: float = 25.0
    humidity: float = 50.0
    last_transmission: float = 0.0
    join_status: bool = False
    data_rate: int = 0  # 0-7 for EU868
    next_tx_time: float = 0.0  # Duty-cycle constrained next allowed TX time
    
    def __post_init__(self):
        if self.dev_eui is None:
            self.dev_eui = get_random_bytes(8)
        if self.app_eui is None:
            self.app_eui = get_random_bytes(8)
        if self.keys is None:
            self.keys = LoRaWANKeys(
                app_key=get_random_bytes(16),
                nwk_key=get_random_bytes(16),
                app_session_key=get_random_bytes(32),  # ChaCha20 requires 32 bytes
                nwk_session_key=get_random_bytes(32)   # ChaCha20 requires 32 bytes
            )

@dataclass
class EnhancedLoRaGateway:
    """Enhanced LoRa gateway model"""
    gateway_id: str
    location: Tuple[float, float]
    coverage_radius: float
    frequency_plan: str = "EU868"
    max_snr: float = 10.0
    min_snr: float = -20.0
    noise_floor: float = -120.0  # dBm

@dataclass
class EnhancedLoRaPacket:
    """Enhanced LoRa packet model"""
    device_id: str
    timestamp: float
    device_class: DeviceClass
    encryption_scheme: str
    dev_eui: bytes
    fcnt: int
    payload_length: int
    encrypted_payload_length: int
    encryption_time_ns: int
    transmission_time_s: float
    energy_consumption_nj: float
    packet_loss: bool = False
    gateway_id: Optional[str] = None
    snr: float = 0.0
    rssi: float = 0.0
    data_rate: int = 0
    frequency: float = 868.0
    mic_valid: bool = True
    packet_type: str = "DATA_UP"
    sf: int = 7
    bandwidth_hz: int = 125000
    rx_power_dbm: float = -120.0

class EnhancedLoRaChannelModel:
    """Enhanced LoRa channel model"""
    
    def __init__(self):
        self.frequency = 868e6  # Hz
        self.path_loss_exponent = 2.7
        self.shadowing_std = 4.0  # dB
        # Receiver noise figure (NF) in dB, used with thermal noise density -174 dBm/Hz
        self.noise_figure_db = 6.0
        self.interference_sources = []
        
    def calculate_path_loss(self, distance: float) -> float:
        """Log-distance path loss with 1 m reference and log-normal shadowing.

        PL(d) = FSPL(1 m) + 10*n*log10(d/1 m) + X_sigma
        where FSPL(1 m) depends on frequency.
        """
        d_m = max(distance, 1.0)
        c = 299792458.0
        wavelength = c / self.frequency
        # FSPL at 1 meter: 20*log10(4*pi*1m / lambda)
        fspl_1m_db = 20.0 * math.log10(4.0 * math.pi / wavelength)
        # Log-distance model term
        log_distance_term = 10.0 * self.path_loss_exponent * math.log10(d_m / 1.0)
        # Log-normal shadowing
        shadowing_db = random.gauss(0.0, self.shadowing_std)
        return fspl_1m_db + log_distance_term + shadowing_db
    
    def calculate_noise_floor(self, bandwidth_hz: float) -> float:
        """Thermal noise floor in dBm for a given bandwidth, including receiver NF.

        N_dBm = -174 + 10*log10(BW_Hz) + NF_dB
        """
        return -174.0 + 10.0 * math.log10(max(bandwidth_hz, 1.0)) + self.noise_figure_db

    def calculate_rx_power_dbm(self, tx_power_dbm: float, distance: float) -> float:
        """Received power in dBm from TX power and path loss."""
        path_loss_db = self.calculate_path_loss(distance)
        return tx_power_dbm - path_loss_db

    def calculate_snr(self, tx_power: float, distance: float, bandwidth_hz: float) -> float:
        """Calculate signal-to-noise ratio using thermal noise law."""
        rx_power = self.calculate_rx_power_dbm(tx_power, distance)
        noise_power = self.calculate_noise_floor(bandwidth_hz)
        snr = rx_power - noise_power
        # Add small random fluctuation to reflect short-term fading
        snr += random.gauss(0.0, 1.0)
        return snr

    def link_budget(self, tx_power_dbm: float, distance_m: float, bandwidth_hz: float, frequency_hz: Optional[float] = None) -> Tuple[float, float, float]:
        """Unified link budget calculation in one shot so shadowing is consistent.

        Returns (rx_dbm, noise_dbm, snr_db).
        """
        d_m = max(distance_m, 1.0)
        freq = float(frequency_hz) if frequency_hz is not None else float(self.frequency)
        c = 299792458.0
        wavelength = c / freq
        fspl_1m_db = 20.0 * math.log10(4.0 * math.pi / wavelength)
        pl_db = fspl_1m_db + 10.0 * self.path_loss_exponent * math.log10(d_m) + random.gauss(0.0, self.shadowing_std)
        rx_dbm = tx_power_dbm - pl_db
        noise_dbm = self.calculate_noise_floor(bandwidth_hz)
        snr_db = rx_dbm - noise_dbm + random.gauss(0.0, 1.0)
        return rx_dbm, noise_dbm, snr_db
    
    def calculate_packet_error_rate(self, snr: float, spreading_factor: int) -> float:
        """PER with hard SNR demodulation thresholds and margin-based decay.

        Typical LoRa demodulation thresholds (dB):
        SF7≈-7.5, SF8≈-10, SF9≈-12.5, SF10≈-15, SF11≈-17.5, SF12≈-20
        """
        min_snr_threshold = {
            7: -7.5, 8: -10.0, 9: -12.5, 10: -15.0, 11: -17.5, 12: -20.0
        }[spreading_factor]
        margin = snr - min_snr_threshold
        if margin < 0:
            return 1.0
        # Light PER decreasing with SNR margin; cap to a small floor
        per = 0.3 * math.exp(-0.35 * margin)
        return max(0.001, min(1.0, per))

class ADRController:
    """Adaptive Data Rate controller"""
    
    def __init__(self):
        self.snr_margin = 10.0  # dB
        self.min_snr = {
            7: -7.5, 8: -10.0, 9: -12.5, 10: -15.0, 11: -17.5, 12: -20.0
        }
    
    def calculate_optimal_sf(self, avg_snr: float) -> int:
        """Calculate optimal spreading factor"""
        for sf in [7, 8, 9, 10, 11, 12]:
            if avg_snr >= self.min_snr[sf] + self.snr_margin:
                return sf
        return 12  # Most conservative choice
    
    def should_adjust_power(self, avg_snr: float, current_sf: int) -> Tuple[bool, float]:
        """Determine if transmission power should be adjusted"""
        target_snr = self.min_snr[current_sf] + self.snr_margin
        if avg_snr > target_snr + 5:  # Signal too strong
            power_reduction = min(3.0, avg_snr - target_snr - 2)
            return True, -power_reduction
        return False, 0.0

class EnhancedLoRaNetworkSimulator:
    """Enhanced LoRa network simulator"""
    
    def __init__(self, area_size: Tuple[float, float] = (1000, 1000), seed: Optional[int] = None):
        self.area_size = area_size
        self.devices: List[EnhancedLoRaDevice] = []
        self.gateways: List[EnhancedLoRaGateway] = []
        self.packets: List[EnhancedLoRaPacket] = []
        self.simulation_time = 0.0
        self.simulation_duration = 300.0  # Default simulation duration
        self.time_step = 1.0
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)
        
        # Channel model
        self.channel_model = EnhancedLoRaChannelModel()
        
        # ADR controller
        self.adr_controller = ADRController()
        
        # Regulatory duty cycle (EU868 common sub-band 1%)
        self.duty_cycle = 0.01
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'successful_transmissions': 0,
            'failed_transmissions': 0,
            'encryption_performance': {},
            'adr_adjustments': 0,
            'join_requests': 0,
            'join_accepts': 0
        }
        
        # Encryption scheme performance data (based on real tests)
        self.encryption_performance = {
            'AES-128-GCM': {'encrypt_time': 85000, 'decrypt_time': 25000, 'overhead': 16},
            'ChaCha20-Poly1305': {'encrypt_time': 69266, 'decrypt_time': 19800, 'overhead': 0},
            'Hybrid-ECC-AES': {'encrypt_time': 40566, 'decrypt_time': 16066, 'overhead': 21},
            'Advanced-ECC-AES': {'encrypt_time': 1537533, 'decrypt_time': 599266, 'overhead': 152},
            'ChaCha20-Poly1305-Lite': {'encrypt_time': 160900, 'decrypt_time': 67133, 'overhead': 48}
        }
        
        # Frequency plan (EU868)
        self.frequencies = [868.1, 868.3, 868.5, 867.1, 867.3, 867.5, 867.7, 867.9]
        
        # Device SNR history
        self.device_snr_history: Dict[str, List[float]] = {}

    def calculate_distance(self, pos1: Tuple[float, float], pos2: Tuple[float, float]) -> float:
        """Calculate distance between two points"""
        return np.sqrt((pos1[0] - pos2[0])**2 + (pos1[1] - pos2[1])**2)

    def calculate_packet_duration(self, packet_size: int, spreading_factor: LoRaSpreadingFactor,
                                bandwidth: LoRaBandwidth,
                                coding_rate: int = 1,  # CR=1→4/5, 2→4/6, 3→4/7, 4→4/8
                                header_enabled: bool = True,
                                crc_enabled: bool = True,
                                preamble_symbols: int = 8) -> float:
        """LoRa Time-on-Air per Semtech formula.

        Tsym = 2^SF / BW
        payloadSymbNb = 8 + max(ceil((8*PL - 4*SF + 28 + 16*CRC - 20*H) / (4*(SF - 2*DE))) * (CR + 4), 0)
        ToA = (preamble+4.25)*Tsym + payloadSymbNb*Tsym
        """
        sf = int(spreading_factor.value)
        bw_hz = int(bandwidth.value)
        tsym = (2 ** sf) / float(bw_hz)
        # Low data rate optimization
        de = 1 if (bw_hz == 125000 and sf >= 11) else 0
        h = 0 if header_enabled else 1
        crc = 1 if crc_enabled else 0
        cr = max(1, min(4, int(coding_rate)))
        # Payload symbols
        payload_symb_nb = 8 + max(
            math.ceil(
                (8 * packet_size - 4 * sf + 28 + 16 * crc - 20 * h) /
                (4 * (sf - 2 * de))
            ) * (cr + 4),
            0
        )
        t_preamble = (preamble_symbols + 4.25) * tsym
        t_payload = payload_symb_nb * tsym
        return t_preamble + t_payload

    def calculate_energy_consumption(self, transmission_time: float, transmission_power: float) -> float:
        """Calculate energy consumption (nJ)"""
        power_mw = 10 ** (transmission_power / 10.0)
        # E_nJ = (mW) * s * 1e6
        return power_mw * transmission_time * 1e6

    def _map_sf_bw_to_data_rate(self, sf: int, bw_hz: int) -> int:
        """Map SF/BW to EU868 DR index."""
        if bw_hz == 125000:
            mapping = {12: 0, 11: 1, 10: 2, 9: 3, 8: 4, 7: 5}
            return mapping.get(sf, 5)
        if bw_hz == 250000 and sf == 7:
            return 6
        return 5

    def simulate_join_process(self, device: EnhancedLoRaDevice) -> bool:
        """Simulate device join process with RX1/RX2 timing and exponential backoff"""
        if device.join_status:
            return True
        
        # Initialize join attempt tracking if not exists
        if not hasattr(device, 'join_attempts'):
            device.join_attempts = 0
            device.last_join_attempt = 0.0
            device.join_backoff_time = 0.0
        
        current_time = self.simulation_time
        
        # Check if we're in backoff period
        if current_time < device.join_backoff_time:
            return False
        
        # Simulate Join Request
        self.stats['join_requests'] += 1
        device.join_attempts += 1
        device.last_join_attempt = current_time
        
        # Check if any gateway is in range
        best_gateway = None
        best_snr = -float('inf')
        
        for gateway in self.gateways:
            distance = self.calculate_distance(device.location, gateway.location)
            if distance <= gateway.coverage_radius:
                # Calculate SNR for this gateway
                rx_dbm, noise_dbm, snr = self.channel_model.link_budget(
                    device.transmission_power, distance, int(device.bandwidth.value), 
                    frequency_hz=868e6  # Join frequency
                )
                if snr > best_snr:
                    best_snr = snr
                    best_gateway = gateway
        
        if best_gateway is None:
            # No gateway in range, apply exponential backoff
            backoff_time = min(300, 2 ** device.join_attempts)  # Cap at 5 minutes
            device.join_backoff_time = current_time + backoff_time
            return False
        
        # Simulate RX1 window (1 second after Join Request)
        rx1_time = current_time + 1.0
        rx1_success = False
        
        if rx1_time <= self.simulation_duration:
            # Check if Join Accept can be received in RX1
            # RX1 uses same frequency and DR as Join Request
            rx1_snr = best_snr  # Same SNR as uplink
            rx1_per = self.channel_model.calculate_packet_error_rate(rx1_snr, device.spreading_factor.value)
            rx1_success = random.random() > rx1_per
        
        # If RX1 fails, try RX2 window (2 seconds after Join Request)
        if not rx1_success:
            rx2_time = current_time + 2.0
            if rx2_time <= self.simulation_duration:
                # RX2 uses fixed frequency and DR
                rx2_freq = 869.525  # EU868 RX2 frequency
                rx2_dr = 8  # DR8 (SF12, BW125)
                
                # Recalculate SNR for RX2 frequency
                distance = self.calculate_distance(device.location, best_gateway.location)
                rx2_rx_dbm, rx2_noise_dbm, rx2_snr = self.channel_model.link_budget(
                    best_gateway.transmission_power, distance, 125000, frequency_hz=rx2_freq * 1e6
                )
                rx2_per = self.channel_model.calculate_packet_error_rate(rx2_snr, 12)  # SF12
                rx1_success = random.random() > rx2_per
        
        if rx1_success:
            # Join successful
            self.stats['join_accepts'] += 1
            device.join_status = True
            device.join_attempts = 0  # Reset for potential rejoin
            return True
        else:
            # Join failed, apply exponential backoff
            backoff_time = min(300, 2 ** device.join_attempts)  # Cap at 5 minutes
            device.join_backoff_time = current_time + backoff_time
            return False

    def simulate_packet_transmission(self, device: EnhancedLoRaDevice, current_time: float) -> Optional[EnhancedLoRaPacket]:
        """Simulate single packet transmission"""
        
        # Check if it's time to transmit
        if current_time - device.last_transmission < device.transmission_interval:
            return None
        # Duty cycle gate
        if current_time < getattr(device, 'next_tx_time', 0.0):
            return None
        
        # If device not joined, try to join first
        if not device.join_status:
            if not self.simulate_join_process(device):
                return None
        
        # Generate more frequent business traffic for joined devices
        # Class A devices: every 15-30 seconds (increased frequency)
        # Class B devices: every 30-60 seconds  
        # Class C devices: every 45-90 seconds
        if device.join_status:
            class_intervals = {
                DeviceClass.CLASS_A: (15, 30),  # More frequent for Class A
                DeviceClass.CLASS_B: (30, 60),
                DeviceClass.CLASS_C: (45, 90)
            }
            min_interval, max_interval = class_intervals.get(device.device_class, (15, 30))
            
            # Override transmission interval for joined devices to generate more traffic
            if current_time - device.last_transmission >= random.uniform(min_interval, max_interval):
                pass  # Allow transmission
            else:
                return None
        
        # Create LoRaWAN packet
        payload = get_random_bytes(device.packet_size)
        lora_packet = LoRaWANPacket(device.dev_eui, payload, device.keys.fcnt_up)
        
        # Get encryption scheme and encrypt
        scheme = get_encryption_scheme(device.encryption_scheme)
        encrypted_packet, encryption_time = scheme.encrypt(lora_packet, device.keys.app_session_key)
        
        # Calculate transmission time using dynamic encryption overhead
        base_len = len(encrypted_packet.encrypted_payload) if encrypted_packet.encrypted_payload else len(payload)
        mic_len = len(encrypted_packet.mic) if getattr(encrypted_packet, 'mic', None) is not None else 0
        nonce_len = len(encrypted_packet.nonce) if getattr(encrypted_packet, 'nonce', None) is not None else 0
        scheme_name = device.encryption_scheme
        # Determine if MIC and nonce are embedded in the packet
        mic_embedded = scheme_name in {"Hybrid-ECC-AES", "ChaCha20-Poly1305-Lite"}
        nonce_embedded = scheme_name in {"Hybrid-ECC-AES", "Advanced-ECC-AES", "ChaCha20-Poly1305-Lite"}
        total_on_air_bytes = base_len + (0 if mic_embedded else mic_len) + (0 if nonce_embedded else nonce_len)
        transmission_time = self.calculate_packet_duration(
            total_on_air_bytes, device.spreading_factor, device.bandwidth
        )
        
        # Calculate energy consumption
        energy_consumption = self.calculate_energy_consumption(
            transmission_time, device.transmission_power
        )
        
        # Select frequency and compute time window
        tx_freq = random.choice(self.frequencies)
        t_start = current_time
        t_end = t_start + transmission_time

        # Unified link budget; pick best gateway by SNR
        best_gateway = None
        best_tuple = None  # (snr, rx_dbm, noise_dbm, distance)
        packet_loss = True
        bw_hz = int(device.bandwidth.value)
        for gateway in self.gateways:
            distance = self.calculate_distance(device.location, gateway.location)
            if distance > gateway.coverage_radius:
                continue
            rx_dbm, noise_dbm, snr = self.channel_model.link_budget(
                device.transmission_power, distance, bw_hz, frequency_hz=tx_freq * 1e6
            )
            if (best_tuple is None) or (snr > best_tuple[0]):
                best_tuple = (snr, rx_dbm, noise_dbm, distance)
                best_gateway = gateway

        if best_gateway is None:
            return None

        best_snr, best_rx_power, best_noise, _ = best_tuple
        per = self.channel_model.calculate_packet_error_rate(best_snr, device.spreading_factor.value)
        packet_loss = (random.random() < per)
        
        # Update device SNR history
        if device.device_id not in self.device_snr_history:
            self.device_snr_history[device.device_id] = []
        self.device_snr_history[device.device_id].append(best_snr)
        
        # Limit history length
        if len(self.device_snr_history[device.device_id]) > 20:
            self.device_snr_history[device.device_id] = self.device_snr_history[device.device_id][-20:]
        
        # ADR adjustment with more frequent triggers
        if device.adr_enabled and len(self.device_snr_history[device.device_id]) >= 5:  # Reduced from 10 to 5
            # Use last 5 packets for faster ADR response
            recent_snr = self.device_snr_history[device.device_id][-5:]
            avg_snr = np.mean(recent_snr)
            snr_std = np.std(recent_snr)
            
            # More aggressive ADR: trigger if SNR is stable and good
            if snr_std < 2.0:  # SNR is stable (low variance)
                optimal_sf = self.adr_controller.calculate_optimal_sf(avg_snr)
                
                if optimal_sf != device.spreading_factor.value:
                    old_sf = device.spreading_factor.value
                    device.spreading_factor = LoRaSpreadingFactor(optimal_sf)
                    self.stats['adr_adjustments'] += 1
                    print(f"📡 Device {device.device_id} ADR: SF{old_sf} -> SF{optimal_sf} (SNR: {avg_snr:.1f}±{snr_std:.1f}dB)")

        # Duty cycle next allow time (ETSI 1%): wait from TX end
        if self.duty_cycle > 0:
            device.next_tx_time = t_end + transmission_time * (1.0 / self.duty_cycle - 1.0)

        # Update DR index after any ADR changes
        device.data_rate = self._map_sf_bw_to_data_rate(device.spreading_factor.value, int(device.bandwidth.value))
        
        # Create simulation packet record
        packet = EnhancedLoRaPacket(
            device_id=device.device_id,
            timestamp=current_time,
            device_class=device.device_class,
            encryption_scheme=device.encryption_scheme,
            dev_eui=device.dev_eui,
            fcnt=device.keys.fcnt_up,
            payload_length=device.packet_size,
            encrypted_payload_length=total_on_air_bytes,
            encryption_time_ns=encryption_time,
            transmission_time_s=transmission_time,
            energy_consumption_nj=energy_consumption,
            packet_loss=packet_loss,
            gateway_id=best_gateway.gateway_id if best_gateway else None,
            snr=best_snr,
            rssi=best_rx_power,
            data_rate=device.data_rate,
            frequency=tx_freq,
            sf=device.spreading_factor.value,
            bandwidth_hz=int(device.bandwidth.value),
            rx_power_dbm=best_rx_power
        )
        # Attach time window
        setattr(packet, 'tx_start', t_start)
        setattr(packet, 'tx_end', t_end)
        
        # Update device status
        device.keys.fcnt_up += 1
        # Duty cycle waiting starts from TX end
        if self.duty_cycle > 0:
            device.next_tx_time = t_end + transmission_time * (1.0 / self.duty_cycle - 1.0)
        device.last_transmission = t_end
        device.battery_level -= energy_consumption / 1000000  # Simplified battery consumption
        
        return packet

    def simulate_network(self, duration: float):
        """Simulate entire network"""
        print(f"Starting enhanced LoRa network simulation, duration: {duration} seconds")
        self.simulation_duration = duration
        
        for t in np.arange(0, duration, self.time_step):
            self.simulation_time = float(t)
            
            # Each device attempts transmission; collect to resolve collisions afterwards
            new_packets: List[EnhancedLoRaPacket] = []
            for device in self.devices:
                packet = self.simulate_packet_transmission(device, float(t))
                if packet:
                    new_packets.append(packet)

            # Collision and capture effect: same freq & SF at same gateway with ToA overlap
            capture_threshold_db = 6.0
            groups: Dict[Tuple[str, float, int], List[EnhancedLoRaPacket]] = {}
            for p in new_packets:
                if not p.gateway_id:
                    continue
                key = (p.gateway_id, p.frequency, p.sf)
                groups.setdefault(key, []).append(p)
            for _, pkts in groups.items():
                if len(pkts) <= 1:
                    continue
                # Sort by start time to find overlapping windows
                pkts.sort(key=lambda x: getattr(x, 'tx_start', x.timestamp))
                overlapping_sets: List[List[EnhancedLoRaPacket]] = []
                cur = [pkts[0]]
                for p in pkts[1:]:
                    prev_end = getattr(cur[-1], 'tx_end', cur[-1].timestamp + cur[-1].transmission_time_s)
                    if getattr(p, 'tx_start', p.timestamp) < prev_end:
                        cur.append(p)
                    else:
                        overlapping_sets.append(cur)
                        cur = [p]
                overlapping_sets.append(cur)

                # Apply capture in each overlapping set
                for overlap in overlapping_sets:
                    if len(overlap) <= 1:
                        continue
                    overlap.sort(key=lambda x: x.rx_power_dbm, reverse=True)
                    if overlap[0].rx_power_dbm - overlap[1].rx_power_dbm >= capture_threshold_db:
                        for loser in overlap[1:]:
                            loser.packet_loss = True
                    else:
                        for loser in overlap:
                            loser.packet_loss = True

            # Commit packets and update stats
            for packet in new_packets:
                self.packets.append(packet)
                self.stats['total_packets'] += 1
                if not packet.packet_loss:
                    self.stats['successful_transmissions'] += 1
                else:
                    self.stats['failed_transmissions'] += 1
            
            # Show progress
            if int(t) % max(1, int(duration / 10)) == 0:
                print(f"Simulation progress: {t/duration*100:.1f}%")

    def generate_network_scenario(self, num_devices: int = 20, num_gateways: int = 3):
        """Generate network scenario"""
        print(f"Generating enhanced network scenario: {num_devices} devices, {num_gateways} gateways")
        
        # Add gateways
        for i in range(num_gateways):
            gateway = EnhancedLoRaGateway(
                gateway_id=f"GW_{i+1}",
                location=(random.uniform(0, self.area_size[0]), 
                         random.uniform(0, self.area_size[1])),
                coverage_radius=500
            )
            self.gateways.append(gateway)
        
        # Add devices
        encryption_schemes = list(self.encryption_performance.keys())
        spreading_factors = list(LoRaSpreadingFactor)
        bandwidths = list(LoRaBandwidth)
        device_classes = list(DeviceClass)
        
        for i in range(num_devices):
            # Bias towards Class A devices (most common in LoRaWAN)
            device_class_weights = {
                DeviceClass.CLASS_A: 0.7,  # 70% Class A devices
                DeviceClass.CLASS_B: 0.2,  # 20% Class B devices
                DeviceClass.CLASS_C: 0.1   # 10% Class C devices
            }
            device_class = random.choices(
                list(device_class_weights.keys()), 
                weights=list(device_class_weights.values())
            )[0]
            
            device = EnhancedLoRaDevice(
                device_id=f"DEV_{i+1:03d}",
                location=(random.uniform(0, self.area_size[0]), 
                         random.uniform(0, self.area_size[1])),
                device_class=device_class,
                spreading_factor=random.choice(spreading_factors),
                bandwidth=random.choice(bandwidths),
                transmission_power=random.uniform(10, 14),
                encryption_scheme=random.choice(encryption_schemes),
                packet_size=random.randint(10, 50),
                transmission_interval=random.choice([30, 60, 120])  # 30 seconds, 1 minute, 2 minutes
            )
            self.devices.append(device)
        
        print("Enhanced network scenario generation completed")

    def calculate_statistics(self):
        """Calculate network statistics"""
        # Statistics by encryption scheme
        for scheme in self.encryption_performance.keys():
            scheme_packets = [p for p in self.packets if p.encryption_scheme == scheme]
            if scheme_packets:
                self.stats['encryption_performance'][scheme] = {
                    'total_packets': len(scheme_packets),
                    'successful': len([p for p in scheme_packets if not p.packet_loss]),
                    'success_rate': len([p for p in scheme_packets if not p.packet_loss]) / len(scheme_packets),
                    'average_encryption_time': np.mean([p.encryption_time_ns for p in scheme_packets]),
                    'average_transmission_time': np.mean([p.transmission_time_s for p in scheme_packets]),
                    'average_energy': np.mean([p.energy_consumption_nj for p in scheme_packets]),
                    'average_overhead': np.mean([p.encrypted_payload_length - p.payload_length for p in scheme_packets]),
                    'average_snr': np.mean([p.snr for p in scheme_packets]),
                    'average_rssi': np.mean([p.rssi for p in scheme_packets])
                }

    def generate_report(self, security_assessments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate simulation report"""
        self.calculate_statistics()
        
        report = {
            'simulation_info': {
                'duration': self.simulation_time,
                'total_devices': len(self.devices),
                'total_gateways': len(self.gateways),
                'area_size': self.area_size,
                'simulator_type': 'Enhanced LoRaWAN'
            },
            'network_statistics': {
                'total_packets': self.stats['total_packets'],
                'successful_transmissions': self.stats['successful_transmissions'],
                'failed_transmissions': self.stats['failed_transmissions'],
                'overall_success_rate': self.stats['successful_transmissions'] / max(self.stats['total_packets'], 1),
                'join_requests': self.stats['join_requests'],
                'join_accepts': self.stats['join_accepts'],
                'adr_adjustments': self.stats['adr_adjustments']
            },
            'encryption_performance': self.stats['encryption_performance'],
            'device_statistics': self._get_device_statistics(),
            'recommendation': self._generate_recommendation(security_assessments)
        }
        
        return report

    def save_communication_log(self, filename: str):
        """Save communication log to CSV file"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'timestamp', 'device_id', 'dev_eui', 'fcnt', 'encryption_scheme',
                'payload_length', 'encrypted_payload_length', 'encryption_time_ns',
                'transmission_time_s', 'energy_consumption_nj', 'packet_loss', 'gateway_id',
                'snr', 'rssi', 'data_rate', 'frequency', 'sf', 'bandwidth_hz', 'rx_power_dbm',
                'tx_start', 'tx_end'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for packet in self.packets:
                writer.writerow({
                    'timestamp': packet.timestamp,
                    'device_id': packet.device_id,
                    'dev_eui': packet.dev_eui.hex(),
                    'fcnt': packet.fcnt,
                    'encryption_scheme': packet.encryption_scheme,
                    'payload_length': packet.payload_length,
                    'encrypted_payload_length': packet.encrypted_payload_length,
                    'encryption_time_ns': packet.encryption_time_ns,
                    'transmission_time_s': packet.transmission_time_s,
                    'energy_consumption_nj': packet.energy_consumption_nj,
                    'packet_loss': packet.packet_loss,
                    'gateway_id': packet.gateway_id or '',
                    'snr': packet.snr,
                    'rssi': packet.rssi,
                    'data_rate': packet.data_rate,
                    'frequency': packet.frequency,
                    'sf': getattr(packet, 'sf', 7),
                    'bandwidth_hz': getattr(packet, 'bandwidth_hz', 125000),
                    'rx_power_dbm': getattr(packet, 'rx_power_dbm', packet.rssi),
                    'tx_start': getattr(packet, 'tx_start', packet.timestamp),
                    'tx_end': getattr(packet, 'tx_end', packet.timestamp + packet.transmission_time_s)
                })
        
        print(f"Communication log saved to: {filename}")

    def save_simulation_report(self, filename: str, security_assessments: Optional[Dict[str, Any]] = None):
        """Save simulation report to JSON file"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        report = self.generate_report(security_assessments)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"Simulation report saved to: {filename}")

    def _get_device_statistics(self) -> Dict[str, Any]:
        """Get device statistics"""
        device_stats = {
            'class_a_count': len([d for d in self.devices if d.device_class == DeviceClass.CLASS_A]),
            'class_b_count': len([d for d in self.devices if d.device_class == DeviceClass.CLASS_B]),
            'class_c_count': len([d for d in self.devices if d.device_class == DeviceClass.CLASS_C]),
            'joined_devices': len([d for d in self.devices if d.join_status]),
            'average_battery': np.mean([d.battery_level for d in self.devices]),
            'sf_distribution': {}
        }
        
        # Spreading factor distribution
        for sf in LoRaSpreadingFactor:
            device_stats['sf_distribution'][f'SF{sf.value}'] = len([d for d in self.devices if d.spreading_factor == sf])
        
        return device_stats

    def _generate_recommendation(self, security_assessments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate recommendation scheme using comprehensive scoring"""
        if not self.stats['encryption_performance']:
            return {'recommended_scheme': 'None', 'reason': 'No data available'}
        
        # Use the comprehensive scoring method from metrics.py
        from utils.metrics import PerformanceMetrics
        metrics = PerformanceMetrics()
        
        # Calculate comprehensive score including security assessments
        recommendation = metrics.calculate_comprehensive_score(
            self.stats['encryption_performance'], 
            security_assessments
        )
        
        # If security assessments are missing, provide a warning
        if recommendation.get('error') == 'missing_security_assessments':
            recommendation['warning'] = 'Security tests must be run for accurate recommendations'
            recommendation['recommended_scheme'] = 'None'
            recommendation['reason'] = 'Security assessment required for comprehensive evaluation'
        
        return recommendation
