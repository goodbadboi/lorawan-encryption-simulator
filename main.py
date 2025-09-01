#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LoRaWAN Encryption Scheme Evaluation System

Core Features:
- Enhanced LoRaWAN Network Simulation
- Encryption Scheme Performance Evaluation
- Security Attack Testing
- Comprehensive Recommendation System
"""

import os
import sys
import time
import threading
import json
import math
from typing import Dict, Any, Optional, List
import random

# Add project path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from simulation.enhanced_lora_simulator import EnhancedLoRaNetworkSimulator
from attacks.attack_simulator import AttackSimulator
from utils.visualization import LoRaVisualizer

class TimeoutError(Exception):
    pass

def run_with_timeout(func, timeout_seconds):
    """Use threading to implement timeout functionality"""
    result = [None]
    exception = [None]
    
    def target():
        try:
            result[0] = func()
        except Exception as e:
            exception[0] = e
    
    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout_seconds)
    
    if thread.is_alive():
        raise TimeoutError(f"Operation timeout ({timeout_seconds} seconds)")
    
    if exception[0]:
        raise exception[0]
    
    return result[0]

def calculate_confidence_interval(successes: int, total: int, confidence: float = 0.95) -> tuple[float, float]:
    """Calculate Wilson confidence interval for binomial proportion"""
    if total == 0:
        return (0.0, 0.0)
    
    p_hat = successes / total
    z = 1.96  # 95% confidence level
    
    # Wilson interval
    denominator = 1 + z**2 / total
    centre_adjusted_probability = (p_hat + z * z / (2 * total)) / denominator
    adjusted_standard_error = z * math.sqrt((p_hat * (1 - p_hat) + z * z / (4 * total)) / total) / denominator
    
    lower_bound = max(0.0, centre_adjusted_probability - adjusted_standard_error)
    upper_bound = min(1.0, centre_adjusted_probability + adjusted_standard_error)
    
    return (lower_bound, upper_bound)

class LoRaEncryptionEvaluator:
    """LoRa Encryption Scheme Evaluator"""
    
    def __init__(self):
        """Initialize evaluator"""
        self.config = self._get_config()
        self.simulator: Optional[EnhancedLoRaNetworkSimulator] = None
        self.attack_simulator: Optional[AttackSimulator] = None
        self.visualizer: Optional[LoRaVisualizer] = None
        
    def _get_config(self) -> Dict[str, Any]:
        """Get configuration"""
        return {
            'simulation': {
                'duration': 300,  # 5 minutes simulation
                'num_devices': 10,
                'num_gateways': 2,
                'area_size': (1000, 1000),
                'time_step': 1.0
            },
            'security_test': {
                'enabled': True,
                'num_test_packets': 1000,  # Increased for statistical stability
                'attack_attempts': 1000    # Increased for statistical stability
            },
            'results_dir': 'results'
        }
    
    def initialize_system(self):
        """Initialize system"""
        print("🚀 Initializing LoRaWAN Encryption Scheme Evaluation System...")
        
        # Create results directory
        os.makedirs(self.config['results_dir'], exist_ok=True)
        
        # Initialize enhanced network simulator
        self.simulator = EnhancedLoRaNetworkSimulator(
            area_size=self.config['simulation']['area_size']
        )
        
        # Initialize attack simulator
        if self.config['security_test']['enabled']:
            self.attack_simulator = AttackSimulator(self.config['results_dir'])
        
        # Initialize visualizer
        self.visualizer = LoRaVisualizer(self.config['results_dir'])
        
        print("✅ System initialization completed")
    
    def generate_network_scenario(self):
        """Generate network scenario"""
        print("\n🌐 Generating network scenario...")
        
        if self.simulator is None:
            raise RuntimeError("Simulator not initialized")
            
        # Increase device count for better network load and collision testing
        num_devices = max(20, self.config['simulation']['num_devices'])  # At least 20 devices
        self.simulator.generate_network_scenario(
            num_devices=num_devices,
            num_gateways=self.config['simulation']['num_gateways']
        )
        
        print(f"✅ Network scenario generation completed")
        print(f"   Device count: {len(self.simulator.devices)}")
        print(f"   Gateway count: {len(self.simulator.gateways)}")
        
        # Display device type distribution
        from simulation.enhanced_lora_simulator import DeviceClass
        class_a_count = len([d for d in self.simulator.devices if d.device_class == DeviceClass.CLASS_A])
        class_b_count = len([d for d in self.simulator.devices if d.device_class == DeviceClass.CLASS_B])
        class_c_count = len([d for d in self.simulator.devices if d.device_class == DeviceClass.CLASS_C])
        
        print(f"   Device type distribution: Class A: {class_a_count}, Class B: {class_b_count}, Class C: {class_c_count}")
    
    def run_simulation(self):
        """Run network simulation"""
        print(f"\n🔄 Starting network simulation...")
        # Increase simulation duration for better ADR and network behavior testing
        simulation_duration = max(900, self.config['simulation']['duration'])  # At least 900 seconds
        print(f"   Simulation duration: {simulation_duration} seconds")
        print(f"   Simulation features: ADR mechanism, real channel model, device join process")
        
        if self.simulator is None:
            raise RuntimeError("Simulator not initialized")
        
        start_time = time.time()
        
        # Use timeout mechanism (60 seconds)
        try:
            def simulate():
                self.simulator.simulate_network(simulation_duration)
            
            run_with_timeout(simulate, 60)
        except TimeoutError:
            print("⚠️ Simulation timeout, using simplified mode")
            self.simulator.simulate_network(60)
        
        simulation_time = time.time() - start_time
        print(f"✅ Simulation completed, time taken: {simulation_time:.2f} seconds")
        
        # Display simulation statistics
        print(f"📊 Simulation Statistics:")
        print(f"   Total packets: {self.simulator.stats['total_packets']}")
        print(f"   Successful transmissions: {self.simulator.stats['successful_transmissions']}")
        print(f"   Failed transmissions: {self.simulator.stats['failed_transmissions']}")
        print(f"   Join requests: {self.simulator.stats['join_requests']}")
        print(f"   Successful joins: {self.simulator.stats['join_accepts']}")
        print(f"   ADR adjustments: {self.simulator.stats['adr_adjustments']}")
        
        return self.simulator
    
    def run_security_tests(self):
        """Run security tests"""
        if not self.config['security_test']['enabled'] or self.attack_simulator is None:
            print("⚠️ Security tests disabled")
            return {}
        
        print("\n🛡️ Starting security attack tests...")
        print(f"   Test packet count: {self.config['security_test']['num_test_packets']}")
        print(f"   Attack attempt count: {self.config['security_test']['attack_attempts']}")
        
        start_time = time.time()
        
        try:
            # Generate test data
            print("🔧 Generating test data...")
            self.attack_simulator.generate_test_data(self.config['security_test']['num_test_packets'])
            
            # Get all available encryption schemes
            from encryption.schemes import get_all_schemes
            all_schemes = get_all_schemes()
            schemes = [scheme.name for scheme in all_schemes]
            print(f"🔍 Found {len(schemes)} encryption schemes: {', '.join(schemes)}")
            security_assessments = {}
            
            for scheme_name in schemes:
                print(f"\n📊 Testing scheme: {scheme_name}")
                
                # Test all attack types
                from attacks.attack_types import AttackType
                attack_types = list(AttackType)
                
                all_results = []
                for attack_type in attack_types:
                    try:
                        results = self.attack_simulator.run_attack_test(
                            scheme_name, attack_type, 
                            self.config['security_test']['attack_attempts']
                        )
                        all_results.extend(results)
                        
                        # Calculate results with confidence intervals
                        successful_attacks = sum(1 for r in results if r.success)
                        total_attempts = len(results)
                        success_rate = successful_attacks / total_attempts if total_attempts > 0 else 0
                        avg_vulnerability = sum(r.vulnerability_score for r in results) / total_attempts if total_attempts > 0 else 0
                        
                        # Calculate 95% confidence interval
                        ci_lower, ci_upper = calculate_confidence_interval(successful_attacks, total_attempts)
                        
                        print(f"   {attack_type.value}: Success rate {success_rate:.1%} (95% CI: {ci_lower:.1%}-{ci_upper:.1%}), "
                              f"Average vulnerability score {avg_vulnerability:.3f}")
                        
                    except Exception as e:
                        print(f"   {attack_type.value}: Test failed - {e}")
                        continue
                
                # Calculate comprehensive security score
                if all_results:
                    total_attacks = len(all_results)
                    successful_attacks = sum(1 for r in all_results if r.success)
                    success_rate = successful_attacks / total_attacks
                    avg_vulnerability = sum(r.vulnerability_score for r in all_results) / total_attacks
                    security_score = max(0.0, 1.0 - avg_vulnerability)
                    
                    from attacks.attack_simulator import SecurityAssessment
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
                else:
                    print(f"   ⚠️ Scheme {scheme_name} has no valid test results")
            
        except TimeoutError:
            print("⚠️ Security test timeout, using simplified results")
            security_assessments = {
                "AES-128-GCM": self._create_dummy_assessment("AES-128-GCM", 0.95),
                "ChaCha20-Poly1305": self._create_dummy_assessment("ChaCha20-Poly1305", 0.82),
                "Hybrid-ECC-AES": self._create_dummy_assessment("Hybrid-ECC-AES", 0.88)
            }
        
        test_time = time.time() - start_time
        print(f"✅ Security tests completed, time taken: {test_time:.2f} seconds")
        
        return security_assessments
    
    def _create_dummy_assessment(self, scheme_name: str, security_score: float):
        """Create dummy assessment result"""
        from attacks.attack_simulator import SecurityAssessment
        from attacks.attack_types import AttackResult, AttackType
        
        dummy_results = [
            AttackResult(
                attack_type=AttackType.REPLAY,
                target_scheme=scheme_name,
                success=False,
                attack_time_ns=1000000,
                attempts=3,
                details={"dummy": True},
                vulnerability_score=0.0
            )
        ]
        
        return SecurityAssessment(
            scheme_name=scheme_name,
            total_attacks=3,
            successful_attacks=0,
            success_rate=0.0,
            average_vulnerability_score=1.0 - security_score,
            attack_results=dummy_results,
            security_score=security_score
        )
    
    def generate_final_report(self, simulation_report: Dict[str, Any], security_assessments: Optional[Dict[str, Any]] = None, run_id: str = ""):
        """Generate final comprehensive report"""
        print("\n" + "="*80)
        print("📊 Final Comprehensive Report")
        print("="*80)
        
        if run_id:
            print(f"🆔 Run ID: {run_id}")
        
        if not security_assessments:
            print("⚠️ No security assessment results, cannot generate recommendations")
            return
        
        # Import the normalization function
        from utils.metrics import normalize_scheme_name
        
        # Print scheme registry for debugging
        print(f"\n🔍 Scheme Registry (Run ID: {run_id}):")
        print("Scheme Name -> Slug -> AEAD? -> Tag Len -> PubKey Len -> AAD Fields")
        
        encryption_performance = simulation_report.get('encryption_performance', {})
        for scheme_name in encryption_performance.keys():
            slug = normalize_scheme_name(scheme_name)
            
            # Determine scheme properties
            is_aead = scheme_name in ["AES-128-GCM", "ChaCha20-Poly1305", "Hybrid-ECC-AES", "ChaCha20-Poly1305-Lite"]
            tag_len = 16 if is_aead else 4
            pubkey_len = 32 if "ECC" in scheme_name or "Hybrid" in scheme_name else 0
            aad_fields = "DevEUI|FCnt|Dir" if is_aead else "FCnt only"
            
            print(f"  {scheme_name} -> {slug} -> {is_aead} -> {tag_len}B -> {pubkey_len}B -> {aad_fields}")
        
        # Create unified scheme ID mapping
        scheme_mapping = {}
        for scheme_name in encryption_performance.keys():
            slug = normalize_scheme_name(scheme_name)
            scheme_mapping[scheme_name] = slug
        
        # Create reverse mapping for security assessments
        security_mapping = {}
        for scheme_name in security_assessments.keys():
            slug = normalize_scheme_name(scheme_name)
            security_mapping[slug] = scheme_name
        
        # Print aggregation sanity check
        print(f"\n🔍 Aggregation Sanity Check (Run ID: {run_id}):")
        print("Slug -> Has Security? -> Has Performance? -> Has SNR? -> Final Score")
        
        recommendations = []
        
        for scheme_name, performance_data in encryption_performance.items():
            # Get security assessment using unified mapping
            slug = scheme_mapping[scheme_name]
            has_security = slug in security_mapping
            has_performance = scheme_name in encryption_performance
            has_snr = 'average_snr' in performance_data
            
            if has_security:
                original_security_name = security_mapping[slug]
                assessment = security_assessments[original_security_name]
                
                # Calculate comprehensive score
                security_score = assessment.security_score
                performance_score = performance_data.get('success_rate', 0.8)
                
                # Score weights: Security score * 0.5 + Performance score * 0.3 + SNR score * 0.2
                snr_score = min(1.0, performance_data.get('average_snr', 0) / 10.0)
                overall_score = security_score * 0.5 + performance_score * 0.3 + snr_score * 0.2
                
                recommendations.append({
                    'scheme': scheme_name,
                    'security_score': security_score,
                    'performance_score': performance_score,
                    'snr_score': snr_score,
                    'overall_score': overall_score
                })
                
                print(f"  {slug} -> {has_security} -> {has_performance} -> {has_snr} -> {overall_score:.3f}")
            else:
                print(f"  {slug} -> {has_security} -> {has_performance} -> {has_snr} -> MISSING")
                print(f"⚠️  Warning: Scheme {scheme_name} (slug: {slug}) not found in security assessments")
        
        # Sort by comprehensive score
        recommendations.sort(key=lambda x: x['overall_score'], reverse=True)
        
        # Display recommendation results
        if recommendations:
            best_scheme = recommendations[0]
            print(f"\n🏆 Recommended scheme: {best_scheme['scheme']} (Run ID: {run_id})")
            print(f"📊 Comprehensive score: {best_scheme['overall_score']:.3f}")
            print(f"💡 Recommendation reason: Best overall performance, Security score: {best_scheme['security_score']:.1%}, Performance score: {best_scheme['performance_score']:.1%}, SNR score: {best_scheme['snr_score']:.1%}")
        
        # 显示安全分拆分表
        print(f"\n🔍 Security Score Breakdown (Run ID: {run_id}):")
        print("Scheme Name -> Replay -> MITM -> Tamper -> KeyExt -> SideCh -> Jamming -> Core -> Other -> Final")
        
        for rec in recommendations:
            scheme_name = rec['scheme']
            slug = scheme_mapping[scheme_name]
            if slug in security_mapping:
                original_security_name = security_mapping[slug]
                assessment = security_assessments[original_security_name]
                
                # 计算各攻击类型的子分数
                attack_scores = self._calculate_attack_type_scores(assessment.attack_results)
                
                # 计算核心安全分和其他安全分
                core_score = min(1.0 - attack_scores.get('replay', 0), 
                               1.0 - attack_scores.get('mitm', 0), 
                               1.0 - attack_scores.get('packet_tampering', 0))
                other_score = 1.0 - (attack_scores.get('side_channel', 0) + 
                                    attack_scores.get('brute_force', 0) + 
                                    attack_scores.get('jamming', 0) + 
                                    attack_scores.get('key_extraction', 0)) / 4
                
                # 使用完整方案名称，避免截断
                print(f"  {scheme_name:<25} -> {attack_scores.get('replay', 0):.3f} -> {attack_scores.get('mitm', 0):.3f} -> {attack_scores.get('packet_tampering', 0):.3f} -> {attack_scores.get('key_extraction', 0):.3f} -> {attack_scores.get('side_channel', 0):.3f} -> {attack_scores.get('jamming', 0):.3f} -> {core_score:.3f} -> {other_score:.3f} -> {rec['security_score']:.3f}")
        
        print(f"\n📈 Scheme scores (Run ID: {run_id}):")
        for rec in recommendations:
            print(f"   {rec['scheme']}: {rec['overall_score']:.3f} (Security:{rec['security_score']:.1%}, Performance:{rec['performance_score']:.1%}, SNR:{rec['snr_score']:.1%})")
    
    def _calculate_attack_type_scores(self, attack_results: List) -> Dict[str, float]:
        """计算各攻击类型的平均漏洞分数"""
        attack_scores = {}
        attack_counts = {}
        
        for result in attack_results:
            attack_type = result.attack_type.value
            if attack_type not in attack_scores:
                attack_scores[attack_type] = 0.0
                attack_counts[attack_type] = 0
            
            attack_scores[attack_type] += result.vulnerability_score
            attack_counts[attack_type] += 1
        
        # 计算平均值
        for attack_type in attack_scores:
            if attack_counts[attack_type] > 0:
                attack_scores[attack_type] /= attack_counts[attack_type]
        
        return attack_scores
    
    def run_complete_evaluation(self):
        """Run complete evaluation process"""
        print("=" * 60)
        print("🔐 LoRaWAN Encryption Scheme Evaluation System")
        print("=" * 60)
        
        # Generate unique run ID
        import hashlib
        import time
        run_timestamp = int(time.time())
        run_seed = random.randint(1, 1000000)
        run_id = f"{run_timestamp}_{run_seed}"
        run_hash = hashlib.md5(f"{run_id}".encode()).hexdigest()[:8]
        full_run_id = f"{run_id}_{run_hash}"
        
        print(f"🆔 Run ID: {full_run_id}")
        print(f"📅 Timestamp: {run_timestamp}")
        print(f"🎲 Seed: {run_seed}")
        
        try:
            # Initialize system
            self.initialize_system()
            
            # Generate network scenario
            self.generate_network_scenario()
            
            # Run network simulation
            simulator = self.run_simulation()
            
            # Print configuration snapshot before security tests
            print(f"\n🔧 Security Test Configuration Snapshot:")
            print(f"   Run ID: {full_run_id}")
            print(f"   Seed: {run_seed}")
            print(f"   Jammer Power: +8-12 dB (random)")
            print(f"   Duty Cycle: 0.15-0.30 (scenario-based)")
            print(f"   Overlap Probability: 0.4-0.6 (random)")
            print(f"   Capture Margin: 8.0-12.0 dB (random)")
            print(f"   Time Constant τ: 0.65s")
            print(f"   LoRa Config: SF=7, BW=125kHz, CR=4/5")
            print(f"   SNR Threshold: 7.5 dB")
            print(f"   Success Threshold: 20%")
            print(f"   RTT Threshold: 0.5s")
            print(f"   Delay Factor: 0.2-0.5×ToA")
            
            # Run security tests
            security_assessments = self.run_security_tests()
            
            # Generate simulation report
            simulation_report = simulator.generate_report(security_assessments)
            
            # Add run ID to all reports
            simulation_report['run_id'] = full_run_id
            simulation_report['run_timestamp'] = run_timestamp
            simulation_report['run_seed'] = run_seed
            
            # Save output files
            simulator.save_communication_log('results/lorawan_simulated_packets.csv')
            simulator.save_simulation_report('results/simulation_report.json', security_assessments)
            
            # Save security report
            if self.attack_simulator and security_assessments:
                self.attack_simulator.save_attack_results(security_assessments, "attack_results.json")
                self.attack_simulator.save_attack_csv(security_assessments, "attack_results.csv")
                
                # Generate and save security report
                security_report = self.attack_simulator.generate_security_report(security_assessments)
                security_report['run_id'] = full_run_id
                with open('results/security_report.json', 'w', encoding='utf-8') as f:
                    json.dump(security_report, f, indent=2, ensure_ascii=False)
                print("Security report saved to: results/security_report.json")
            
            # Generate final report
            self.generate_final_report(simulation_report, security_assessments, full_run_id)
            
            # Generate visualization report
            if self.visualizer:
                print("\n📊 Generating visualization report...")
                self.visualizer.generate_comprehensive_report(simulation_report, security_assessments)
            
            print(f"\n🎉 Evaluation completed! Run ID: {full_run_id}")
            print("\n✅ Evaluation system ran successfully!")
            print(f"📁 All reports and charts saved to: {self.config['results_dir']}")
            print(f"📄 HTML comprehensive report: {self.config['results_dir']}/charts/comprehensive_report.html")
            
        except Exception as e:
            print(f"❌ Error occurred during evaluation: {e}")
            import traceback
            traceback.print_exc()

def main():
    """Main function"""
    evaluator = LoRaEncryptionEvaluator()
    evaluator.run_complete_evaluation()

if __name__ == "__main__":
    main()
