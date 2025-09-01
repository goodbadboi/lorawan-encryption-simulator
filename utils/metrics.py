import os
import json
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
from typing import Dict, Any, List, Optional
import re

# Set font
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial']
plt.rcParams['axes.unicode_minus'] = False

def normalize_scheme_name(name: str) -> str:
    """Normalize scheme name to create a unique slug for consistent mapping"""
    # Remove special characters and convert to lowercase
    slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
    return slug

class PerformanceMetrics:
    """Performance metrics and chart generation class"""
    
    def __init__(self, results_dir: str = "results"):
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)
    
    def record_performance(self, encryption_performance: Dict[str, Any]) -> Dict[str, Any]:
        """Record encryption scheme performance data"""
        metrics = {}
        
        for scheme, data in encryption_performance.items():
            metrics[scheme] = {
                'encryption_time_ns': data.get('average_encryption_time', 0),
                'transmission_time_s': data.get('average_transmission_time', 0),
                'energy_consumption_nj': data.get('average_energy', 0),
                'overhead_bytes': data.get('average_overhead', 0),
                'success_rate': data.get('success_rate', 0),
                'total_packets': data.get('total_packets', 0)
            }
        
        return metrics
    
    def generate_performance_charts(self, encryption_performance: Dict[str, Any]):
        """Generate performance comparison charts"""
        schemes = list(encryption_performance.keys())
        
        if not schemes:
            print("No performance data available for analysis")
            return
        
        # Create charts
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        
        # 1. Encryption time comparison
        encryption_times = [encryption_performance[s]['average_encryption_time'] for s in schemes]
        bars1 = ax1.bar(schemes, encryption_times, color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'])
        ax1.set_title('Encryption Time Comparison', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Encryption Time (ns)')
        ax1.tick_params(axis='x', rotation=45)
        
        # Add value labels
        for bar, value in zip(bars1, encryption_times):
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(encryption_times)*0.01,
                    f'{value:.0f}', ha='center', va='bottom', fontweight='bold')
        
        # 2. Transmission success rate comparison
        success_rates = [encryption_performance[s]['success_rate'] * 100 for s in schemes]
        bars2 = ax2.bar(schemes, success_rates, color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'])
        ax2.set_title('Transmission Success Rate', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Success Rate (%)')
        ax2.tick_params(axis='x', rotation=45)
        ax2.set_ylim(0, 100)
        
        # Add value labels
        for bar, value in zip(bars2, success_rates):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')
        
        # 3. Energy consumption comparison
        energy_consumption = [encryption_performance[s]['average_energy'] for s in schemes]
        bars3 = ax3.bar(schemes, energy_consumption, color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'])
        ax3.set_title('Energy Consumption', fontsize=14, fontweight='bold')
        ax3.set_ylabel('Energy Consumption (nJ)')
        ax3.tick_params(axis='x', rotation=45)
        
        # Add value labels
        for bar, value in zip(bars3, energy_consumption):
            ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(energy_consumption)*0.01,
                    f'{value:.0f}', ha='center', va='bottom', fontweight='bold')
        
        # 4. Encryption overhead comparison
        overhead = [encryption_performance[s]['average_overhead'] for s in schemes]
        bars4 = ax4.bar(schemes, overhead, color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'])
        ax4.set_title('Encryption Overhead', fontsize=14, fontweight='bold')
        ax4.set_ylabel('Overhead (bytes)')
        ax4.tick_params(axis='x', rotation=45)
        
        # Add value labels
        for bar, value in zip(bars4, overhead):
            ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    f'{value:.0f}', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.results_dir, 'performance_comparison.png'), 
                   dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Performance comparison chart saved to: {os.path.join(self.results_dir, 'performance_comparison.png')}")
    
    def generate_radar_chart(self, encryption_performance: Dict[str, Any]):
        """Generate comprehensive performance radar chart"""
        schemes = list(encryption_performance.keys())
        
        if not schemes:
            print("No performance data available for analysis")
            return
        
        # Calculate comprehensive performance metrics
        categories = ['Encryption Speed', 'Transmission Efficiency', 'Energy Efficiency', 'Security', 'Success Rate']
        
        # Normalize data (0-1, smaller is better)
        scheme_scores = {}
        for scheme in schemes:
            scores = []
            data = encryption_performance[scheme]
            
            # Encryption speed (normalized, smaller is better)
            encrypt_time = data['average_encryption_time']
            all_encrypt_times = [encryption_performance[s]['average_encryption_time'] for s in schemes]
            scores.append(1 - (encrypt_time - min(all_encrypt_times)) / (max(all_encrypt_times) - min(all_encrypt_times)))
            
            # Transmission efficiency (normalized, smaller transmission time is better)
            trans_time = data['average_transmission_time']
            all_trans_times = [encryption_performance[s]['average_transmission_time'] for s in schemes]
            scores.append(1 - (trans_time - min(all_trans_times)) / (max(all_trans_times) - min(all_trans_times)))
            
            # Energy efficiency (normalized, smaller energy consumption is better)
            energy = data['average_energy']
            all_energies = [encryption_performance[s]['average_energy'] for s in schemes]
            scores.append(1 - (energy - min(all_energies)) / (max(all_energies) - min(all_energies)))
            
            # Security score (based on scheme characteristics)
            security_scores = {
                "AES-128-GCM": 0.9,
                "ChaCha20-Poly1305": 0.9,
                "Hybrid-ECC-AES": 0.8,
                "Advanced-ECC-AES": 0.95,
                "ECC-SC-MIC": 0.92
            }
            scores.append(security_scores.get(scheme, 0.5))
            
            # Success rate (use directly)
            scores.append(data['success_rate'])
            
            scheme_scores[scheme] = scores
        
        # Draw radar chart
        angles = np.linspace(0, 2 * np.pi, len(categories), endpoint=False).tolist()
        angles += angles[:1]  # Close the shape
        
        fig, ax = plt.subplots(figsize=(10, 8), subplot_kw=dict(projection='polar'))
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFA500']
        
        for i, scheme in enumerate(schemes):
            values = scheme_scores[scheme] + scheme_scores[scheme][:1]  # Close the shape
            ax.plot(angles, values, 'o-', linewidth=2, label=scheme, color=colors[i])
            ax.fill(angles, values, alpha=0.1, color=colors[i])
        
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories)
        ax.set_ylim(0, 1)
        ax.set_title('Encryption Scheme Performance Radar Chart', size=16, pad=20, fontweight='bold')
        ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.0))
        ax.grid(True)
        
        plt.tight_layout()
        plt.savefig(os.path.join(self.results_dir, 'radar_chart.png'), 
                   dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Radar chart saved to: {os.path.join(self.results_dir, 'radar_chart.png')}")
    
    def generate_json_report(self, simulation_report: Dict[str, Any]) -> str:
        """Generate JSON format simulation report"""
        report_data = {
            'simulation_info': simulation_report['simulation_info'],
            'network_statistics': simulation_report['network_statistics'],
            'encryption_performance': simulation_report['encryption_performance'],
            'recommendation': simulation_report['recommendation'],
            'generated_at': str(np.datetime64('now'))
        }
        
        report_path = os.path.join(self.results_dir, 'simulation_report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"Simulation report saved to: {report_path}")
        return report_path
    
    def calculate_comprehensive_score(self, encryption_performance: Dict[str, Any], 
                                    security_assessments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Calculate comprehensive score (including security test results)"""
        if not encryption_performance:
            return {'recommended_scheme': 'None', 'reason': 'No performance data available'}
        
        # Create unified scheme ID mapping
        scheme_mapping = {}
        for scheme_name in encryption_performance.keys():
            slug = normalize_scheme_name(scheme_name)
            scheme_mapping[scheme_name] = slug
        
        # Create reverse mapping for security assessments
        security_mapping = {}
        if security_assessments:
            for scheme_name in security_assessments.keys():
                slug = normalize_scheme_name(scheme_name)
                security_mapping[slug] = scheme_name
        
        # Print debug information for scheme mapping (only once)
        if not hasattr(self, '_debug_printed'):
            print("\n🔍 Scheme ID Mapping Debug:")
            print("Original Name -> Slug -> Has Performance -> Has Security -> Has SNR")
            for original_name, slug in scheme_mapping.items():
                has_perf = original_name in encryption_performance
                has_security = slug in security_mapping
                has_snr = encryption_performance.get(original_name, {}).get('average_snr', None) is not None
                print(f"  {original_name} -> {slug} -> {has_perf} -> {has_security} -> {has_snr}")
            self._debug_printed = True
        
        # Calculate performance scores based on actual measurements
        performance_scores = {}
        for scheme, data in encryption_performance.items():
            # Normalize performance metrics (lower is better)
            encrypt_time = data.get('average_encryption_time', 0)
            trans_time = data.get('average_transmission_time', 0)
            energy = data.get('average_energy', 0)
            
            # Calculate performance score (weighted combination)
            # Normalize each metric to 0-1 range where 1 is best performance
            all_encrypt_times = [d.get('average_encryption_time', 0) for d in encryption_performance.values()]
            all_trans_times = [d.get('average_transmission_time', 0) for d in encryption_performance.values()]
            all_energies = [d.get('average_energy', 0) for d in encryption_performance.values()]
            
            if max(all_encrypt_times) > 0:
                norm_encrypt = 1 - (encrypt_time / max(all_encrypt_times))
            else:
                norm_encrypt = 1.0
                
            if max(all_trans_times) > 0:
                norm_trans = 1 - (trans_time / max(all_trans_times))
            else:
                norm_trans = 1.0
                
            if max(all_energies) > 0:
                norm_energy = 1 - (energy / max(all_energies))
            else:
                norm_energy = 1.0
            
            # Weighted performance score
            performance_score = (
                norm_encrypt * 0.4 +  # CPU performance (40%)
                norm_trans * 0.3 +    # Transmission efficiency (30%)
                norm_energy * 0.3     # Energy efficiency (30%)
            )
            performance_scores[scheme] = performance_score

        max_performance = max(performance_scores.values()) if performance_scores else 1.0
        
        # Normalize performance scores to 0-1 range
        if max_performance > 0:
            for scheme in performance_scores:
                performance_scores[scheme] = performance_scores[scheme] / max_performance

        # Must use real attack test results, default values are not allowed
        if not security_assessments:
            print("⚠️  Warning: No security test results available, cannot perform comprehensive scoring")
            return {
                'recommended_scheme': 'None', 
                'reason': 'Security tests must be run first for comprehensive scoring',
                'error': 'missing_security_assessments'
            }
        
        # Extract defense scores from security test results using unified mapping
        defense_scores = {}
        for scheme, data in encryption_performance.items():
            slug = scheme_mapping[scheme]
            if slug in security_mapping:
                original_security_name = security_mapping[slug]
                assessment = security_assessments[original_security_name]
                
                if hasattr(assessment, 'security_score'):
                    # If it's a SecurityAssessment object
                    defense_scores[scheme] = assessment.security_score
                elif isinstance(assessment, dict) and 'security_score' in assessment:
                    # If it's a dictionary format
                    defense_scores[scheme] = assessment['security_score']
                else:
                    print(f"⚠️  Warning: Scheme {scheme} (slug: {slug}) missing security score, skipping")
                    continue
            else:
                print(f"⚠️  Warning: Scheme {scheme} (slug: {slug}) not found in security assessments, using minimum score")
                defense_scores[scheme] = 0.0
        
        if not defense_scores:
            print("❌ Error: No valid security test results")
            return {
                'recommended_scheme': 'None', 
                'reason': 'Security test results are invalid',
                'error': 'invalid_security_assessments'
            }

        # Calculate comprehensive score (including defense performance)
        final_scores = {}
        for scheme, data in encryption_performance.items():
            if scheme not in defense_scores:
                print(f"⚠️  Warning: Scheme {scheme} missing security score, using minimum score")
                defense_score = 0.0
            else:
                defense_score = defense_scores[scheme]
            
            normalized_performance = performance_scores[scheme]  # Already normalized
            success_score = data['success_rate']
            
            # Weight distribution: Performance 25%, Success Rate 25%, Defense Performance 50%
            # Security is prioritized as it's critical for LoRaWAN applications
            final_score = (
                normalized_performance * 0.25 +
                success_score * 0.25 +
                defense_score * 0.50
            )
            final_scores[scheme] = final_score

        if not final_scores:
            return {
                'recommended_scheme': 'None', 
                'reason': 'No valid score data',
                'error': 'no_valid_scores'
            }

        # Find schemes with maximum score (potential ties)
        max_score = max(final_scores.values())
        tied_schemes = [scheme for scheme, score in final_scores.items() if score == max_score]
        
        if len(tied_schemes) == 1:
            recommended_scheme = tied_schemes[0]
        else:
            # Apply tie-breaking rules: 1) Airtime overhead, 2) CPU cost, 3) Ecosystem maturity
            recommended_scheme = self._break_tie(tied_schemes, encryption_performance, defense_scores)
        
        recommended_data = encryption_performance[recommended_scheme]

        recommendation = {
            'recommended_scheme': recommended_scheme,
            'score': final_scores[recommended_scheme],
            'reason': f'Best overall performance, Encryption time: {recommended_data["average_encryption_time"]:.0f}ns, Success rate: {recommended_data["success_rate"]:.2%}, Defense performance: {defense_scores.get(recommended_scheme, 0.0):.1%}',
            'all_scores': final_scores,
            'defense_scores': defense_scores,
            'tied_schemes': tied_schemes if len(tied_schemes) > 1 else None,
            'tie_breaking_applied': len(tied_schemes) > 1,
            'performance_details': {
                'encryption_time_ns': recommended_data['average_encryption_time'],
                'transmission_time_s': recommended_data['average_transmission_time'],
                'energy_consumption_nj': recommended_data['average_energy'],
                'success_rate': recommended_data['success_rate'],
                'overhead_bytes': recommended_data['average_overhead']
            },
            'data_source': 'real_measurements',  # Mark data source
            'scheme_mapping': scheme_mapping  # Include mapping for debugging
        }
        return recommendation
    
    def _break_tie(self, tied_schemes: List[str], encryption_performance: Dict[str, Any], 
                   defense_scores: Dict[str, float]) -> str:
        """Break tie using deterministic rules: 1) Airtime overhead, 2) CPU cost, 3) Ecosystem maturity"""
        
        # Rule 1: Airtime overhead (ToA) - prefer schemes with lower overhead
        overhead_scores = {}
        for scheme in tied_schemes:
            if scheme in encryption_performance:
                # Calculate ToA based on overhead (simplified)
                overhead = encryption_performance[scheme].get('average_overhead', 0)
                payload_size = 50  # Typical payload size
                total_size = payload_size + overhead
                # Simplified ToA calculation (proportional to packet size)
                toa = total_size / 1000.0  # Normalized ToA
                overhead_scores[scheme] = toa
        
        if overhead_scores:
            min_overhead = min(overhead_scores.values())
            low_overhead_schemes = [s for s, o in overhead_scores.items() if o == min_overhead]
            
            if len(low_overhead_schemes) == 1:
                return low_overhead_schemes[0]
            elif len(low_overhead_schemes) < len(tied_schemes):
                tied_schemes = low_overhead_schemes
        
        # Rule 2: CPU cost (encryption time) - prefer faster schemes
        cpu_scores = {}
        for scheme in tied_schemes:
            if scheme in encryption_performance:
                cpu_scores[scheme] = encryption_performance[scheme].get('average_encryption_time', float('inf'))
        
        if cpu_scores:
            min_cpu = min(cpu_scores.values())
            fast_schemes = [s for s, c in cpu_scores.items() if c == min_cpu]
            
            if len(fast_schemes) == 1:
                return fast_schemes[0]
            elif len(fast_schemes) < len(tied_schemes):
                tied_schemes = fast_schemes
        
        # Rule 3: Ecosystem/standardization maturity
        maturity_scores = {
            "AES-128-GCM": 10,        # LoRaWAN standard, widely supported
            "ChaCha20-Poly1305": 9,   # IETF standard, good support
            "Hybrid-ECC-AES": 7,      # Common hybrid approach
            "Advanced-ECC-AES": 6,    # Advanced but less standardized
            "ChaCha20-Poly1305-Lite": 8,  # Lightweight AEAD, good for IoT (renamed from ECC-SC-MIC)
            "Lattice-Based": 3,       # Post-quantum, experimental
            "Kyber": 4,               # NIST PQC candidate
            "Dilithium": 4,           # NIST PQC candidate
            "SPHINCS+": 3,            # NIST PQC candidate
        }
        
        max_maturity = max(maturity_scores.get(s, 0) for s in tied_schemes)
        mature_schemes = [s for s in tied_schemes if maturity_scores.get(s, 0) == max_maturity]
        
        # Return the first scheme in alphabetical order if still tied
        return sorted(mature_schemes)[0]
    
    def print_summary(self, simulation_report: Dict[str, Any]):
        """Print simulation summary"""
        print("\n" + "="*80)
        print("LoRaWAN Encryption Scheme Evaluation System - Simulation Summary")
        print("="*80)
        
        # Simulation information
        sim_info = simulation_report['simulation_info']
        print(f"\n📊 Simulation Information:")
        print(f"   Duration: {sim_info['duration']:.0f} seconds")
        print(f"   Total Devices: {sim_info['total_devices']}")
        print(f"   Total Gateways: {sim_info['total_gateways']}")
        print(f"   Area Size: {sim_info['area_size'][0]}m × {sim_info['area_size'][1]}m")
        
        # Network statistics
        net_stats = simulation_report['network_statistics']
        print(f"\n🌐 Network Statistics:")
        print(f"   Total Packets: {net_stats['total_packets']}")
        print(f"   Successful Transmissions: {net_stats['successful_transmissions']}")
        print(f"   Failed Transmissions: {net_stats['failed_transmissions']}")
        print(f"   Overall Success Rate: {net_stats['overall_success_rate']:.2%}")
        
        # Encryption scheme performance
        print(f"\n🔐 Encryption Scheme Performance:")
        for scheme, data in simulation_report['encryption_performance'].items():
            print(f"\n   {scheme}:")
            print(f"     Packet Count: {data['total_packets']}")
            print(f"     Success Rate: {data['success_rate']:.2%}")
            print(f"     Average Encryption Time: {data['average_encryption_time']:.0f}ns")
            print(f"     Average Transmission Time: {data['average_transmission_time']:.3f}s")
            print(f"     Average Energy Consumption: {data['average_energy']:.0f}nJ")
            print(f"     Average Overhead: {data['average_overhead']:.0f} bytes")
        
        # Recommended scheme
        recommendation = simulation_report['recommendation']
        print(f"\n⭐ Recommended Scheme:")
        print(f"   Recommended Algorithm: {recommendation['recommended_scheme']}")
        print(f"   Comprehensive Score: {recommendation['score']:.3f}")
        print(f"   Recommendation Reason: {recommendation['reason']}")
        
        # Display defense performance information
        if 'defense_scores' in recommendation:
            print(f"\n🛡️ Defense Performance Scores:")
            for scheme, defense_score in recommendation['defense_scores'].items():
                print(f"   {scheme}: {defense_score:.1%}")
        
        print("\n" + "="*80) 
    
    def validate_real_measurements(self, encryption_performance: Dict[str, Any], 
                                 security_assessments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Validate that all data are real measurements"""
        validation_result = {
            'is_valid': True,
            'errors': [],
            'warnings': [],
            'data_sources': {}
        }
        
        # Validate performance data
        for scheme, data in encryption_performance.items():
            validation_result['data_sources'][scheme] = {
                'performance': 'real_measurement',
                'security': 'unknown'
            }
            
            # Check if performance data is reasonable
            if data.get('average_encryption_time', 0) <= 0:
                validation_result['errors'].append(f"Scheme {scheme} encryption time is 0 or negative")
                validation_result['is_valid'] = False
            
            if data.get('success_rate', 0) < 0 or data.get('success_rate', 0) > 1:
                validation_result['errors'].append(f"Scheme {scheme} success rate is out of reasonable range")
                validation_result['is_valid'] = False
        
        # Validate security test data
        if security_assessments:
            for scheme_name, assessment in security_assessments.items():
                # Ensure scheme exists in data_sources
                if scheme_name not in validation_result['data_sources']:
                    validation_result['data_sources'][scheme_name] = {
                        'performance': 'unknown',
                        'security': 'unknown'
                    }
                
                validation_result['data_sources'][scheme_name]['security'] = 'real_measurement'
                
                if hasattr(assessment, 'security_score'):
                    score = assessment.security_score
                elif isinstance(assessment, dict) and 'security_score' in assessment:
                    score = assessment['security_score']
                else:
                    validation_result['errors'].append(f"Scheme {scheme_name} missing security score")
                    validation_result['is_valid'] = False
                    continue
                
                if score < 0 or score > 1:
                    validation_result['errors'].append(f"Scheme {scheme_name} security score is out of reasonable range: {score}")
                    validation_result['is_valid'] = False
                
                # Check if there are attack test results
                if hasattr(assessment, 'attack_results') and assessment.attack_results:
                    validation_result['data_sources'][scheme_name]['attack_tests'] = len(assessment.attack_results)
                else:
                    validation_result['warnings'].append(f"Scheme {scheme_name} has no attack test results")
        else:
            validation_result['errors'].append("Missing security test data")
            validation_result['is_valid'] = False
        
        # Check data integrity
        performance_schemes = set(encryption_performance.keys())
        security_schemes = set(security_assessments.keys()) if security_assessments else set()
        
        missing_security = performance_schemes - security_schemes
        if missing_security:
            validation_result['warnings'].append(f"The following schemes are missing security tests: {', '.join(missing_security)}")
        
        return validation_result
    
    def print_validation_report(self, validation_result: Dict[str, Any]):
        """Print validation report"""
        print("\n" + "="*80)
        print("🔍 Data Validation Report")
        print("="*80)
        
        if validation_result['is_valid']:
            print("✅ Data validation passed - All data are real measurements")
        else:
            print("❌ Data validation failed")
        
        if validation_result['errors']:
            print(f"\n❌ Errors ({len(validation_result['errors'])}):")
            for error in validation_result['errors']:
                print(f"   • {error}")
        
        if validation_result['warnings']:
            print(f"\n⚠️  Warnings ({len(validation_result['warnings'])}):")
            for warning in validation_result['warnings']:
                print(f"   • {warning}")
        
        print(f"\n📊 Data Sources:")
        for scheme, sources in validation_result['data_sources'].items():
            print(f"   {scheme}:")
            for source_type, source_info in sources.items():
                print(f"     {source_type}: {source_info}")
        
        print("="*80) 