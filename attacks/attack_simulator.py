#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LoRaWAN Attack Simulator

Provides unified attack testing interface, supporting batch testing and result analysis for multiple attack types.
"""

import time
import json
import csv
import math
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path

from encryption.schemes import LoRaWANPacket, get_encryption_scheme, get_all_schemes
from .attack_types import (
    AttackType, AttackResult, ReplayAttack, ManInTheMiddleAttack,
    BruteForceAttack, SideChannelAttack, PacketTamperingAttack,
    JammingAttack, KeyExtractionAttack
)


@dataclass
class SecurityAssessment:
    """Security assessment result"""
    scheme_name: str
    total_attacks: int
    successful_attacks: int
    success_rate: float
    average_vulnerability_score: float
    attack_results: List[AttackResult]
    security_score: float  # 0.0-1.0, higher means more secure


class AttackSimulator:
    """Attack simulator"""
    
    def __init__(self, results_dir: str = "results"):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(exist_ok=True)
        
        # Initialize all attack types
        self.attacks = {
            AttackType.REPLAY: ReplayAttack(),
            AttackType.MAN_IN_THE_MIDDLE: ManInTheMiddleAttack(),
            AttackType.BRUTE_FORCE: BruteForceAttack(),
            AttackType.SIDE_CHANNEL: SideChannelAttack(),
            AttackType.PACKET_TAMPERING: PacketTamperingAttack(),
            AttackType.JAMMING: JammingAttack(),
            AttackType.KEY_EXTRACTION: KeyExtractionAttack()
        }
        
        # Store test packets
        self.test_packets: List[LoRaWANPacket] = []
        self.test_keys: Dict[str, bytes] = {}
    
    def generate_test_data(self, num_packets: int = 50):
        """Generate test data"""
        print(f"🔧 Generating {num_packets} test packets...")
        
        schemes = get_all_schemes()
        
        for i in range(num_packets):
            # Generate test packets for each encryption scheme
            for scheme in schemes:
                # Generate random payload
                payload_size = 20 + (i % 30)  # 20-50 bytes
                payload = b'TEST_DATA_' + str(i).encode() + b'_' * (payload_size - len(f'TEST_DATA_{i}'))
                
                # Create packet
                dev_eui = b'DEVICE' + str(i % 10).encode().zfill(2)
                packet = LoRaWANPacket(dev_eui=dev_eui, payload=payload, fcnt=i)
                
                # Generate key (adjust length based on scheme)
                if scheme.name in ["ChaCha20-Poly1305", "Hybrid-ECC-AES", "ChaCha20-Poly1305-Lite", "Lattice-Based", "Kyber", "Dilithium", "SPHINCS+"]:
                    # These schemes use 32-byte key
                    key = b'TEST_KEY_32_' + str(hash(scheme.name) % 1000).encode()
                    if len(key) < 32:
                        key = key + b'\x00' * (32 - len(key))
                    elif len(key) > 32:
                        key = key[:32]
                else:
                    # Other schemes use 16-byte key
                    key = b'TEST_KEY_16_' + str(hash(scheme.name) % 1000).encode()
                    if len(key) < 16:
                        key = key + b'\x00' * (16 - len(key))
                    elif len(key) > 16:
                        key = key[:16]
                
                # Encrypt packet
                encrypted_packet, _ = scheme.encrypt(packet, key)
                
                # Set encryption scheme identifier
                encrypted_packet.encryption_scheme = scheme.name
                
                # Store test data
                self.test_packets.append(encrypted_packet)
                self.test_keys[f"{scheme.name}_{i}"] = key
        
        print(f"✅ Test data generation completed, total {len(self.test_packets)} packets")
    
    def run_attack_test(self, scheme_name: str, attack_type: AttackType, 
                       num_attempts: int = 1000) -> List[AttackResult]:
        """Run single attack test"""
        print(f"🔍 Testing {scheme_name} protection against {attack_type.value} attack...")
        
        results = []
        attack = self.attacks[attack_type]
        
        # Get test packets for this scheme
        scheme_packets = [p for p in self.test_packets if hasattr(p, 'encryption_scheme') and p.encryption_scheme == scheme_name]
        if not scheme_packets:
            # If no specific scheme packets, use all packets
            scheme_packets = self.test_packets[:num_attempts]
        
        for i, packet in enumerate(scheme_packets[:num_attempts]):
            # Get corresponding key
            key = self.test_keys.get(f"{scheme_name}_{i}")
            if key is None:
                # Generate appropriate key length based on scheme
                if scheme_name in ["ChaCha20-Poly1305", "Hybrid-ECC-AES", "ChaCha20-Poly1305-Lite", "Lattice-Based", "Kyber", "Dilithium", "SPHINCS+"]:
                    key = b'DEFAULT_KEY_32_BYTES_FOR_CHACHA20'  # 32字节密钥
                else:
                    key = b'DEFAULT_KEY_16BYTES'  # 16字节密钥
            
            # Execute attack
            result = attack.execute(packet, scheme_name, key)
            results.append(result)
            
            # If it's a replay attack, need to capture packet first
            if attack_type == AttackType.REPLAY and isinstance(attack, ReplayAttack):
                attack.capture_packet(packet)
        
        return results
    
    def run_comprehensive_security_test(self, schemes: Optional[List[str]] = None) -> Dict[str, SecurityAssessment]:
        """Run comprehensive security test"""
        if not schemes:
            schemes = [scheme.name for scheme in get_all_schemes()]
        
        print(f"🛡️ Starting comprehensive security test, testing schemes: {', '.join(schemes)}")
        print("⚠️  Note: Security testing is a necessary component for comprehensive scoring and must be completed successfully")
        
        # Generate test data
        try:
            self.generate_test_data()
        except Exception as e:
            print(f"❌ Failed to generate test data: {e}")
            return {}
        
        if not self.test_packets:
            print("❌ No test packets generated")
            return {}
        
        security_assessments = {}
        failed_schemes = []
        
        for scheme_name in schemes:
            print(f"\n📊 Testing scheme: {scheme_name}")
            
            all_results = []
            attack_failures = 0
            
            # Test each attack type
            for attack_type in AttackType:
                try:
                    results = self.run_attack_test(scheme_name, attack_type)
                    if results:
                        all_results.extend(results)
                        
                        # Calculate results with Wilson confidence interval
                        successful_attacks = sum(1 for r in results if r.success)
                        total_attempts = len(results)
                        success_rate = successful_attacks / total_attempts if total_attempts > 0 else 0
                        avg_vulnerability = sum(r.vulnerability_score for r in results) / total_attempts if total_attempts > 0 else 0
                        
                        # Calculate Wilson confidence interval
                        if total_attempts > 0:
                            z = 1.96  # 95% confidence level
                            denominator = 1 + z**2 / total_attempts
                            centre_adjusted_probability = (success_rate + z * z / (2 * total_attempts)) / denominator
                            adjusted_standard_error = z * math.sqrt((success_rate * (1 - success_rate) + z * z / (4 * total_attempts)) / total_attempts) / denominator
                            
                            lower_bound = max(0.0, centre_adjusted_probability - adjusted_standard_error)
                            upper_bound = min(1.0, centre_adjusted_probability + adjusted_standard_error)
                            
                            print(f"   ✅ {attack_type.value}: Success rate {success_rate:.1%} (95% CI: {lower_bound:.1%}-{upper_bound:.1%}, N={total_attempts}), Average vulnerability score {avg_vulnerability:.3f}")
                        else:
                            print(f"   ✅ {attack_type.value}: Success rate {success_rate:.1%} (N={total_attempts}), Average vulnerability score {avg_vulnerability:.3f}")
                    else:
                        print(f"   ❌ {attack_type.value}: Test failed, no results")
                        attack_failures += 1
                        
                except Exception as e:
                    print(f"   ❌ {attack_type.value}: Test exception - {e}")
                    attack_failures += 1
                    continue
            
            # Check if there are enough test results
            if len(all_results) < len(AttackType) * 0.5:  # At least 50% of attack types have results
                print(f"   ⚠️  Warning: Scheme {scheme_name} has insufficient test results, skipping")
                failed_schemes.append(scheme_name)
                continue
            
            # Calculate comprehensive security score using improved aggregation
            if all_results:
                total_attacks = len(all_results)
                successful_attacks = sum(1 for r in all_results if r.success)
                success_rate = successful_attacks / total_attacks
                avg_vulnerability = sum(r.vulnerability_score for r in all_results) / total_attacks
                
                # Improved security score calculation: "保底门槛+加权"
                security_score = self._calculate_improved_security_score(all_results)
                
                assessment = SecurityAssessment(
                    scheme_name=scheme_name,
                    total_attacks=total_attacks,
                    successful_attacks=successful_attacks,
                    success_rate=success_rate,
                    average_vulnerability_score=avg_vulnerability,
                    attack_results=all_results,
                    security_score=security_score
                )
                
                security_assessments[scheme_name] = assessment
                
                print(f"   📈 Comprehensive security score: {security_score:.3f}")
                print(f"   📊 Total attacks: {total_attacks}, Successful attacks: {successful_attacks}")
            else:
                print(f"   ❌ Scheme {scheme_name} has no valid test results")
                failed_schemes.append(scheme_name)
        
        # Summarize test results
        print(f"\n📋 Security test summary:")
        print(f"   ✅ Successfully tested schemes: {len(security_assessments)}")
        print(f"   ❌ Failed test schemes: {len(failed_schemes)}")
        if failed_schemes:
            print(f"   Failed schemes: {', '.join(failed_schemes)}")
        
        if not security_assessments:
            print("❌ No valid security assessment results generated")
            return {}
        
        print(f"✅ Security testing completed, obtained security scores for {len(security_assessments)} schemes")
        return security_assessments
    
    def _calculate_improved_security_score(self, attack_results: List[AttackResult]) -> float:
        """Calculate improved security score using '保底门槛+加权' approach"""
        # Group results by attack type
        attack_vulnerabilities = {}
        for result in attack_results:
            attack_type = result.attack_type.value
            if attack_type not in attack_vulnerabilities:
                attack_vulnerabilities[attack_type] = []
            attack_vulnerabilities[attack_type].append(result.vulnerability_score)
        
        # Calculate average vulnerability for each attack type
        attack_avg_vulnerabilities = {}
        for attack_type, vulnerabilities in attack_vulnerabilities.items():
            attack_avg_vulnerabilities[attack_type] = sum(vulnerabilities) / len(vulnerabilities)
        
        # Define critical attacks (重放、MITM、篡改)
        critical_attacks = ['replay', 'mitm', 'packet_tampering']
        
        # Calculate core security score (关键属性最小值)
        critical_vulnerabilities = []
        for attack_type in critical_attacks:
            if attack_type in attack_avg_vulnerabilities:
                critical_vulnerabilities.append(attack_avg_vulnerabilities[attack_type])
        
        if not critical_vulnerabilities:
            # If no critical attacks tested, use simple average
            all_vulnerabilities = list(attack_avg_vulnerabilities.values())
            return max(0.0, 1.0 - sum(all_vulnerabilities) / len(all_vulnerabilities))
        
        # Core security score = min(1 - V_replay, 1 - V_mitm, 1 - V_tamper)
        core_security_score = min(1.0 - v for v in critical_vulnerabilities)
        
        # Hard threshold check: if any critical attack has high vulnerability, mark as "not recommended"
        if (attack_avg_vulnerabilities.get('replay', 0) >= 0.05 or 
            attack_avg_vulnerabilities.get('mitm', 0) >= 0.2 or 
            attack_avg_vulnerabilities.get('packet_tampering', 0) >= 0.2):
            # Any critical vulnerability above threshold -> severe penalty
            return core_security_score * 0.3  # Additional penalty for critical failures
        
        # Check if core security is below threshold
        if core_security_score < 0.5:
            # If any critical attack has high vulnerability, overall score is severely penalized
            return core_security_score * 0.5  # Additional penalty for critical failures
        
        # Calculate other attacks (侧信道/暴力/干扰/密钥提取)
        other_attacks = ['side_channel', 'brute_force', 'jamming', 'key_extraction']
        other_vulnerabilities = []
        for attack_type in other_attacks:
            if attack_type in attack_avg_vulnerabilities:
                other_vulnerabilities.append(attack_avg_vulnerabilities[attack_type])
        
        if other_vulnerabilities:
            other_security_score = 1.0 - sum(other_vulnerabilities) / len(other_vulnerabilities)
        else:
            other_security_score = 1.0
        
        # Final score: 70% core security + 30% other security
        final_score = 0.7 * core_security_score + 0.3 * other_security_score
        
        return max(0.0, final_score)
    
    def save_attack_results(self, assessments: Dict[str, SecurityAssessment], 
                          filename: str = "attack_results.json"):
        """Save attack test results"""
        filepath = self.results_dir / filename
        
        # Convert to serializable format
        serializable_results = {}
        for scheme_name, assessment in assessments.items():
            serializable_results[scheme_name] = {
                'scheme_name': assessment.scheme_name,
                'total_attacks': assessment.total_attacks,
                'successful_attacks': assessment.successful_attacks,
                'success_rate': assessment.success_rate,
                'average_vulnerability_score': assessment.average_vulnerability_score,
                'security_score': assessment.security_score,
                'attack_results': [
                    {
                        'attack_type': result.attack_type.value,
                        'success': result.success,
                        'attack_time_ns': result.attack_time_ns,
                        'attempts': result.attempts,
                        'vulnerability_score': result.vulnerability_score,
                        'details': result.details
                    }
                    for result in assessment.attack_results
                ]
            }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(serializable_results, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Attack test results saved to: {filepath}")
    
    def save_attack_csv(self, assessments: Dict[str, SecurityAssessment], 
                       filename: str = "attack_results.csv"):
        """Save attack test results as CSV format"""
        filepath = self.results_dir / filename
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'scheme_name', 'attack_type', 'success', 'attack_time_ns',
                    'attempts', 'vulnerability_score', 'details'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for scheme_name, assessment in assessments.items():
                    for result in assessment.attack_results:
                        writer.writerow({
                            'scheme_name': scheme_name,
                            'attack_type': result.attack_type.value,
                            'success': result.success,
                            'attack_time_ns': result.attack_time_ns,
                            'attempts': result.attempts,
                            'vulnerability_score': result.vulnerability_score,
                            'details': str(result.details)
                        })
            
            print(f"📊 Attack test CSV saved to: {filepath}")
        except PermissionError:
            print(f"⚠️  Warning: Cannot save CSV file {filepath}, file may be in use")
            print("   Attack test results can still be accessed via JSON file")
        except Exception as e:
            print(f"⚠️  Warning: Error occurred while saving CSV file: {e}")
            print("   Attack test results can still be accessed via JSON file")
    
    def generate_security_report(self, assessments: Dict[str, SecurityAssessment]) -> Dict[str, Any]:
        """Generate security assessment report"""
        report = {
            'summary': {
                'total_schemes_tested': len(assessments),
                'total_attack_types': len(AttackType),
                'test_timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'scheme_rankings': [],
            'attack_type_analysis': {},
            'recommendations': []
        }
        
        # Scheme rankings
        sorted_schemes = sorted(
            assessments.items(), 
            key=lambda x: x[1].security_score, 
            reverse=True
        )
        
        for rank, (scheme_name, assessment) in enumerate(sorted_schemes, 1):
            report['scheme_rankings'].append({
                'rank': rank,
                'scheme_name': scheme_name,
                'security_score': assessment.security_score,
                'success_rate': assessment.success_rate,
                'average_vulnerability_score': assessment.average_vulnerability_score
            })
        
        # Attack type analysis
        attack_type_stats = {}
        for attack_type in AttackType:
            attack_type_stats[attack_type.value] = {
                'total_attempts': 0,
                'successful_attempts': 0,
                'average_vulnerability_score': 0.0
            }
        
        for assessment in assessments.values():
            for result in assessment.attack_results:
                attack_type = result.attack_type.value
                attack_type_stats[attack_type]['total_attempts'] += 1
                if result.success:
                    attack_type_stats[attack_type]['successful_attempts'] += 1
                attack_type_stats[attack_type]['average_vulnerability_score'] += result.vulnerability_score
        
        # Calculate averages
        for attack_type in attack_type_stats:
            total = attack_type_stats[attack_type]['total_attempts']
            if total > 0:
                attack_type_stats[attack_type]['average_vulnerability_score'] /= total
        
        report['attack_type_analysis'] = attack_type_stats
        
        # Generate recommendations
        best_scheme = sorted_schemes[0][1]
        worst_scheme = sorted_schemes[-1][1]
        
        report['recommendations'] = [
            f"Recommend using {sorted_schemes[0][0]} as the primary encryption scheme (security score: {best_scheme.security_score:.3f})",
            f"Avoid using {sorted_schemes[-1][0]} as the primary scheme (security score: {worst_scheme.security_score:.3f})",
            f"Most effective attack type: {max(attack_type_stats.items(), key=lambda x: x[1]['average_vulnerability_score'])[0]}",
            f"Most secure attack type: {min(attack_type_stats.items(), key=lambda x: x[1]['average_vulnerability_score'])[0]}"
        ]
        
        return report
    
    def print_security_summary(self, assessments: Dict[str, SecurityAssessment]):
        """Print security test summary"""
        print("\n" + "="*80)
        print("🛡️ LoRaWAN Encryption Scheme Security Assessment Summary")
        print("="*80)
        
        # Scheme rankings
        sorted_schemes = sorted(
            assessments.items(), 
            key=lambda x: x[1].security_score, 
            reverse=True
        )
        
        print(f"\n📊 Scheme security rankings:")
        for rank, (scheme_name, assessment) in enumerate(sorted_schemes, 1):
            print(f"   {rank}. {scheme_name}")
            print(f"      Security score: {assessment.security_score:.3f}")
            print(f"      Attack success rate: {assessment.success_rate:.1%}")
            print(f"      Average vulnerability score: {assessment.average_vulnerability_score:.3f}")
            print(f"      Total attacks: {assessment.total_attacks}")
            print()
        
        # Attack type analysis
        print(f"🔍 Attack type analysis:")
        attack_type_stats = {}
        for assessment in assessments.values():
            for result in assessment.attack_results:
                attack_type = result.attack_type.value
                if attack_type not in attack_type_stats:
                    attack_type_stats[attack_type] = {'total': 0, 'successful': 0, 'vulnerability_sum': 0}
                
                attack_type_stats[attack_type]['total'] += 1
                if result.success:
                    attack_type_stats[attack_type]['successful'] += 1
                attack_type_stats[attack_type]['vulnerability_sum'] += result.vulnerability_score
        
        for attack_type, stats in attack_type_stats.items():
            success_rate = stats['successful'] / stats['total'] if stats['total'] > 0 else 0
            avg_vulnerability = stats['vulnerability_sum'] / stats['total'] if stats['total'] > 0 else 0
            print(f"   {attack_type}: Success rate {success_rate:.1%}, Average vulnerability score {avg_vulnerability:.3f}")
        
        print("\n" + "="*80) 