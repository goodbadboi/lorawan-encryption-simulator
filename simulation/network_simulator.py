import os
import csv
import random
import numpy as np
from enum import Enum
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Any
from Crypto.Random import get_random_bytes

import sys
import os
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

@dataclass
class LoRaDevice:
    """LoRa device model"""
    device_id: str
    location: Tuple[float, float]
    spreading_factor: LoRaSpreadingFactor
    bandwidth: LoRaBandwidth
    transmission_power: float
    encryption_scheme: str
    packet_size: int
    transmission_interval: float
    dev_eui: Optional[bytes] = None
    fcnt: int = 0
    
    def __post_init__(self):
        if self.dev_eui is None:
            self.dev_eui = get_random_bytes(8)

@dataclass
class LoRaGateway:
    """LoRa gateway model"""
    gateway_id: str
    location: Tuple[float, float]
    coverage_radius: float

@dataclass
class LoRaPacket:
    """LoRa packet model"""
    device_id: str
    timestamp: float
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

class LoRaNetworkSimulator:
    """LoRa network simulator"""
    
    def __init__(self, area_size: Tuple[float, float] = (1000, 1000)):
        self.area_size = area_size
        self.devices: List[LoRaDevice] = []
        self.gateways: List[LoRaGateway] = []
        self.packets: List[LoRaPacket] = []
        self.simulation_time = 0.0
        self.time_step = 1.0  # 1 second time step
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'successful_transmissions': 0,
            'failed_transmissions': 0,
            'encryption_performance': {}
        }
        
        # Encryption scheme performance data (based on real tests)
        self.encryption_performance = {
            'AES-128-GCM': {'encrypt_time': 85000, 'decrypt_time': 25000, 'overhead': 16},
            'ChaCha20-Poly1305': {'encrypt_time': 69266, 'decrypt_time': 19800, 'overhead': 0},
            'Hybrid-ECC-AES': {'encrypt_time': 40566, 'decrypt_time': 16066, 'overhead': 21},
            'Advanced-ECC-AES': {'encrypt_time': 1537533, 'decrypt_time': 599266, 'overhead': 152},
            'ChaCha20-Poly1305-Lite': {'encrypt_time': 160900, 'decrypt_time': 67133, 'overhead': 48}
        }

    def calculate_distance(self, pos1: Tuple[float, float], pos2: Tuple[float, float]) -> float:
        """Calculate distance between two points"""
        return np.sqrt((pos1[0] - pos2[0])**2 + (pos1[1] - pos2[1])**2)

    def calculate_packet_duration(self, packet_size: int, spreading_factor: LoRaSpreadingFactor, 
                                 bandwidth: LoRaBandwidth) -> float:
        """Calculate packet transmission time"""
        n_preamble = 8
        n_payload = packet_size
        sf = spreading_factor.value
        bw = bandwidth.value
        
        t_symbol = (2**sf) / bw
        t_preamble = (n_preamble + 4.25) * t_symbol
        n_symbol = 8 + np.ceil((8.0 * n_payload - 4.0 * sf + 28 + 16 - 20) / (4.0 * (sf - 2))) * (1 + 1)
        t_payload = n_symbol * t_symbol
        
        return t_preamble + t_payload

    def calculate_energy_consumption(self, transmission_time: float, transmission_power: float) -> float:
        """Calculate energy consumption (nJ)"""
        power_mw = 10**(transmission_power / 10)
        return power_mw * transmission_time * 1000  # Convert to nJ

    def simulate_packet_transmission(self, device: LoRaDevice, current_time: float) -> Optional[LoRaPacket]:
        """Simulate single packet transmission"""
        
        # Check if it's time to transmit
        if current_time % device.transmission_interval != 0:
            return None
            
        # Create LoRaWAN packet
        payload = get_random_bytes(device.packet_size)
        if device.dev_eui is None:
            device.dev_eui = get_random_bytes(8)
        lora_packet = LoRaWANPacket(device.dev_eui, payload, device.fcnt)
        
        # Get encryption scheme and encrypt
        scheme = get_encryption_scheme(device.encryption_scheme)
        encrypted_packet, encryption_time = scheme.encrypt(lora_packet, get_random_bytes(32))
        
        # Calculate transmission time
        total_packet_size = device.packet_size + self.encryption_performance[device.encryption_scheme]['overhead']
        transmission_time = self.calculate_packet_duration(
            total_packet_size, device.spreading_factor, device.bandwidth
        )
        
        # Calculate energy consumption
        energy_consumption = self.calculate_energy_consumption(
            transmission_time, device.transmission_power
        )
        
        # Check coverage range
        gateway_reached = False
        gateway_id = None
        for gateway in self.gateways:
            distance = self.calculate_distance(device.location, gateway.location)
            if distance <= gateway.coverage_radius:
                gateway_reached = True
                gateway_id = gateway.gateway_id
                break
        
        # Create simulation packet record
        packet = LoRaPacket(
            device_id=device.device_id,
            timestamp=current_time,
            encryption_scheme=device.encryption_scheme,
            dev_eui=device.dev_eui,
            fcnt=device.fcnt,
            payload_length=device.packet_size,
            encrypted_payload_length=len(encrypted_packet.encrypted_payload) if encrypted_packet.encrypted_payload else 0,
            encryption_time_ns=encryption_time,
            transmission_time_s=transmission_time,
            energy_consumption_nj=energy_consumption,
            packet_loss=not gateway_reached,
            gateway_id=gateway_id
        )
        
        # Update device frame counter
        device.fcnt += 1
        
        return packet

    def simulate_network(self, duration: float):
        """Simulate entire network"""
        print(f"Starting LoRa network simulation, duration: {duration} seconds")
        
        for t in np.arange(0, duration, self.time_step):
            self.simulation_time = float(t)
            
            # Each device attempts transmission
            for device in self.devices:
                packet = self.simulate_packet_transmission(device, float(t))
                if packet:
                    self.packets.append(packet)
                    self.stats['total_packets'] += 1
                    
                    if not packet.packet_loss:
                        self.stats['successful_transmissions'] += 1
                    else:
                        self.stats['failed_transmissions'] += 1
            
            # Show progress
            if int(t) % max(1, int(duration / 10)) == 0:  # Show progress every 10%, minimum every 1 second
                print(f"Simulation progress: {t/duration*100:.1f}%")

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
                    'average_overhead': np.mean([p.encrypted_payload_length - p.payload_length for p in scheme_packets])
                }

    def generate_network_scenario(self, num_devices: int = 20, num_gateways: int = 3):
        """Generate network scenario"""
        print(f"Generating network scenario: {num_devices} devices, {num_gateways} gateways")
        
        # Add gateways
        for i in range(num_gateways):
            gateway = LoRaGateway(
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
        
        for i in range(num_devices):
            device = LoRaDevice(
                device_id=f"DEV_{i+1:03d}",
                location=(random.uniform(0, self.area_size[0]), 
                         random.uniform(0, self.area_size[1])),
                spreading_factor=random.choice(spreading_factors),
                bandwidth=random.choice(bandwidths),
                transmission_power=random.uniform(10, 14),
                encryption_scheme=random.choice(encryption_schemes),
                packet_size=random.randint(10, 50),
                transmission_interval=random.choice([300, 900])  # 5 or 15 minutes
            )
            self.devices.append(device)
        
        print("Network scenario generation completed")

    def save_communication_log(self, filename: str):
        """Save communication log to CSV file"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'timestamp', 'device_id', 'dev_eui', 'fcnt', 'encryption_scheme',
                'payload_length', 'encrypted_payload_length', 'encryption_time_ns',
                'transmission_time_s', 'energy_consumption_nj', 'packet_loss', 'gateway_id'
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
                    'gateway_id': packet.gateway_id or ''
                })
        
        print(f"Communication log saved to: {filename}")

    def generate_report(self, security_assessments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate simulation report"""
        self.calculate_statistics()
        
        report = {
            'simulation_info': {
                'duration': self.simulation_time,
                'total_devices': len(self.devices),
                'total_gateways': len(self.gateways),
                'area_size': self.area_size
            },
            'network_statistics': {
                'total_packets': self.stats['total_packets'],
                'successful_transmissions': self.stats['successful_transmissions'],
                'failed_transmissions': self.stats['failed_transmissions'],
                'overall_success_rate': self.stats['successful_transmissions'] / max(self.stats['total_packets'], 1)
            },
            'encryption_performance': self.stats['encryption_performance'],
            'recommendation': self._generate_recommendation(security_assessments)
        }
        
        return report

    def _generate_recommendation(self, security_assessments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate recommendation (including defense performance)"""
        if not self.stats['encryption_performance']:
            return {'recommended_scheme': 'None', 'reason': 'No data available'}
        
        # First calculate all performance scores
        performance_scores = {}
        for scheme, data in self.stats['encryption_performance'].items():
            performance_score = (
                data['average_encryption_time'] * 0.3 +
                data['average_transmission_time'] * 0.2 +
                data['average_energy'] * 0.2
            )
            performance_scores[scheme] = performance_score
        
        max_performance = max(performance_scores.values())
        
        # Must use real attack test results, default values are not allowed
        if not security_assessments:
            print("⚠️  Warning: No security test results, cannot perform comprehensive scoring")
            return {
                'recommended_scheme': 'None', 
                'reason': 'Security tests must be run first for comprehensive scoring',
                'error': 'missing_security_assessments'
            }
        
        # Extract defense scores from security test results
        defense_scores = {}
        for scheme_name, assessment in security_assessments.items():
            if hasattr(assessment, 'security_score'):
                # If it's a SecurityAssessment object
                defense_scores[scheme_name] = assessment.security_score
            elif isinstance(assessment, dict) and 'security_score' in assessment:
                # If it's a dictionary format
                defense_scores[scheme_name] = assessment['security_score']
            else:
                print(f"⚠️  Warning: Scheme {scheme_name} missing security score, skipping")
                continue
        
        if not defense_scores:
            print("❌ Error: No valid security test results")
            return {
                'recommended_scheme': 'None', 
                'reason': 'Security test results are invalid',
                'error': 'invalid_security_assessments'
            }
        
        # Calculate comprehensive score (including defense performance)
        final_scores = {}
        for scheme, data in self.stats['encryption_performance'].items():
            if scheme not in defense_scores:
                print(f"⚠️  Warning: Scheme {scheme} missing security score, using minimum score")
                defense_score = 0.0
            else:
                defense_score = defense_scores[scheme]
            
            normalized_performance = 1 - (performance_scores[scheme] / max_performance)
            success_score = data['success_rate']
            
            # Weight distribution: Performance 20%, Success Rate 30%, Defense Performance 50%
            final_score = (
                normalized_performance * 0.20 +
                success_score * 0.30 +
                defense_score * 0.50
            )
            final_scores[scheme] = final_score
        
        if not final_scores:
            return {
                'recommended_scheme': 'None', 
                'reason': 'No valid score data',
                'error': 'no_valid_scores'
            }
        
        recommended_scheme = max(final_scores.keys(), key=lambda x: final_scores[x])
        recommended_data = self.stats['encryption_performance'][recommended_scheme]
        
        return {
            'recommended_scheme': recommended_scheme,
            'score': final_scores[recommended_scheme],
            'reason': f'Best overall performance, Encryption time: {recommended_data["average_encryption_time"]:.0f}ns, Success rate: {recommended_data["success_rate"]:.2%}, Defense performance: {defense_scores.get(recommended_scheme, 0.0):.1%}',
            'all_scores': final_scores,
            'defense_scores': defense_scores,
            'data_source': 'real_measurements'  # Mark data source
        } 