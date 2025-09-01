#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scenario-based Recommendation System for LoRaWAN Encryption Schemes
Based on actual project data for Chapter 5.3
"""

import os
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple
import json
import pandas as pd

# Set font for Chinese characters
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'SimHei']
plt.rcParams['axes.unicode_minus'] = False

class ScenarioRecommendationSystem:
    """Scenario-based recommendation system for encryption schemes"""
    
    def __init__(self, results_dir: str = "results"):
        self.results_dir = results_dir
        self.scenarios = {
            'low_power_periodic': {
                'name': '低功耗周期上报',
                'description': 'Low-power periodic reporting',
                'requirements': ['energy_efficiency', 'low_overhead', 'basic_security'],
                'priority_weights': {'energy': 0.5, 'overhead': 0.3, 'security': 0.2}
            },
            'stable_long_session': {
                'name': '稳定长会话',
                'description': 'Stable long sessions',
                'requirements': ['forward_secrecy', 'moderate_performance', 'high_security'],
                'priority_weights': {'security': 0.4, 'performance': 0.4, 'overhead': 0.2}
            },
            'high_compliance_long_life': {
                'name': '高合规长寿命',
                'description': 'High compliance and long lifespan',
                'requirements': ['post_quantum_security', 'long_term_protection', 'compliance'],
                'priority_weights': {'security': 0.6, 'compliance': 0.3, 'performance': 0.1}
            }
        }
        
    def load_project_data(self):
        """Load actual project data"""
        sim_report_path = os.path.join(self.results_dir, 'simulation_report.json')
        security_report_path = os.path.join(self.results_dir, 'security_report.json')
        
        with open(sim_report_path, 'r', encoding='utf-8') as f:
            self.sim_data = json.load(f)
        
        with open(security_report_path, 'r', encoding='utf-8') as f:
            self.security_data = json.load(f)
        
        # Extract performance data
        self.performance_data = self.sim_data['encryption_performance']
        
        # Extract security data
        self.security_rankings = {item['scheme_name']: item for item in self.security_data['scheme_rankings']}
    
    def calculate_scenario_score(self, scheme_name: str, scenario: str) -> float:
        """Calculate scenario-specific score for a scheme"""
        if scheme_name not in self.performance_data or scheme_name not in self.security_rankings:
            return 0.0
        
        perf_data = self.performance_data[scheme_name]
        sec_data = self.security_rankings[scheme_name]
        weights = self.scenarios[scenario]['priority_weights']
        
        # Normalize metrics (0-1, higher is better)
        # Energy efficiency (lower energy is better)
        all_energies = [self.performance_data[s]['average_energy'] for s in self.performance_data]
        energy_score = 1.0 - (perf_data['average_energy'] - min(all_energies)) / (max(all_energies) - min(all_energies))
        
        # Overhead efficiency (lower overhead is better)
        all_overheads = [self.performance_data[s]['average_overhead'] for s in self.performance_data]
        overhead_score = 1.0 - (perf_data['average_overhead'] - min(all_overheads)) / (max(all_overheads) - min(all_overheads))
        
        # Security score (higher is better)
        security_score = sec_data['security_score']
        
        # Performance score (lower transmission time is better)
        all_times = [self.performance_data[s]['average_transmission_time'] for s in self.performance_data]
        performance_score = 1.0 - (perf_data['average_transmission_time'] - min(all_times)) / (max(all_times) - min(all_times))
        
        # Calculate weighted score
        if scenario == 'low_power_periodic':
            score = (weights['energy'] * energy_score + 
                    weights['overhead'] * overhead_score + 
                    weights['security'] * security_score)
        elif scenario == 'stable_long_session':
            score = (weights['security'] * security_score + 
                    weights['performance'] * performance_score + 
                    weights['overhead'] * overhead_score)
        else:  # high_compliance_long_life
            score = (weights['security'] * security_score + 
                    weights['compliance'] * security_score + 
                    weights['performance'] * performance_score)
        
        return score
    
    def generate_scenario_recommendation_table(self) -> pd.DataFrame:
        """Generate T7 recommendation table"""
        if not hasattr(self, 'sim_data'):
            self.load_project_data()
        
        # Get all schemes
        schemes = list(self.performance_data.keys())
        
        # Calculate scores for each scenario
        table_data = []
        for scheme in schemes:
            row = {'Scheme': scheme}
            
            # Performance metrics
            perf_data = self.performance_data[scheme]
            row['Energy (mJ)'] = f"{perf_data['average_energy']/1e6:.2f}"
            row['ToA (s)'] = f"{perf_data['average_transmission_time']:.3f}"
            row['Overhead (B)'] = f"{perf_data['average_overhead']:.0f}"
            row['Success Rate (%)'] = f"{perf_data['success_rate']*100:.1f}"
            
            # Security metrics
            sec_data = self.security_rankings[scheme]
            row['Security Score'] = f"{sec_data['security_score']:.3f}"
            row['Attack Success Rate (%)'] = f"{sec_data['success_rate']*100:.1f}"
            
            # Scenario scores
            for scenario in self.scenarios.keys():
                score = self.calculate_scenario_score(scheme, scenario)
                row[f'{scenario}_score'] = f"{score:.3f}"
            
            table_data.append(row)
        
        # Create DataFrame
        df = pd.DataFrame(table_data)
        
        # Add ranking columns
        for scenario in self.scenarios.keys():
            scores = [float(row[f'{scenario}_score']) for row in table_data]
            rankings = np.argsort(scores)[::-1] + 1  # Higher score = better rank
            df[f'{scenario}_rank'] = rankings
        
        return df
    
    def generate_scenario_comparison_chart(self, save_path: str = None):
        """Generate T7 scenario comparison chart"""
        if not hasattr(self, 'sim_data'):
            self.load_project_data()
        
        # Get recommendation data
        df = self.generate_scenario_recommendation_table()
        
        # Prepare data for plotting
        scenarios = list(self.scenarios.keys())
        schemes = df['Scheme'].tolist()
        
        # Create subplot for each scenario
        fig, axes = plt.subplots(1, 3, figsize=(18, 6))
        fig.suptitle('T7: Scenario-based Encryption Scheme Recommendations\n'
                    'Performance Comparison Across Different Application Scenarios', 
                    fontsize=16, fontweight='bold', y=0.98)
        
        colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']
        
        for i, scenario in enumerate(scenarios):
            scores = [float(df.loc[df['Scheme'] == scheme, f'{scenario}_score'].iloc[0]) for scheme in schemes]
            
            bars = axes[i].bar(schemes, scores, color=colors[:len(schemes)], alpha=0.7, edgecolor='black')
            axes[i].set_title(f'{self.scenarios[scenario]["name"]}\n({self.scenarios[scenario]["description"]})', 
                            fontweight='bold', fontsize=12)
            axes[i].set_ylabel('Scenario Score', fontweight='bold')
            axes[i].set_ylim(0, 1.0)
            
            # Add value labels on bars
            for bar, score in zip(bars, scores):
                height = bar.get_height()
                axes[i].text(bar.get_x() + bar.get_width()/2., height + 0.02,
                           f'{score:.3f}', ha='center', va='bottom', fontweight='bold')
            
            # Rotate x-axis labels
            axes[i].tick_params(axis='x', rotation=45)
            
            # Add grid
            axes[i].grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Scenario comparison chart saved to: {save_path}")
        else:
            plt.show()
        
        return fig
    
    def generate_engineering_complexity_analysis(self) -> Dict[str, Dict]:
        """Generate engineering complexity analysis"""
        complexity_data = {
            'AES-128-GCM': {
                'dependencies': 'Low',
                'code_size': 'Small (2-5KB)',
                'key_management': 'Simple',
                'upgrade_cost': 'Low',
                'implementation_time': '1-2 weeks',
                'hardware_requirements': 'AES acceleration preferred'
            },
            'ChaCha20-Poly1305': {
                'dependencies': 'Low',
                'code_size': 'Medium (5-8KB)',
                'key_management': 'Simple',
                'upgrade_cost': 'Low',
                'implementation_time': '2-3 weeks',
                'hardware_requirements': 'None'
            },
            'ChaCha20-Poly1305-Lite': {
                'dependencies': 'Low',
                'code_size': 'Small (3-6KB)',
                'key_management': 'Simple',
                'upgrade_cost': 'Low',
                'implementation_time': '1-2 weeks',
                'hardware_requirements': 'None'
            },
            'Hybrid-ECC-AES': {
                'dependencies': 'Medium',
                'code_size': 'Large (15-25KB)',
                'key_management': 'Complex',
                'upgrade_cost': 'Medium',
                'implementation_time': '4-6 weeks',
                'hardware_requirements': 'ECC acceleration preferred'
            },
            'Advanced-ECC-AES': {
                'dependencies': 'High',
                'code_size': 'Very Large (40-60KB)',
                'key_management': 'Very Complex',
                'upgrade_cost': 'High',
                'implementation_time': '8-12 weeks',
                'hardware_requirements': 'Strong MCU required'
            }
        }
        
        return complexity_data
    
    def generate_complexity_heatmap(self, save_path: str = None):
        """Generate L7 engineering complexity heatmap"""
        complexity_data = self.generate_engineering_complexity_analysis()
        
        # Convert to numerical scores for heatmap
        complexity_scores = {
            'dependencies': {'Low': 1, 'Medium': 2, 'High': 3},
            'code_size': {'Small': 1, 'Medium': 2, 'Large': 3, 'Very Large': 4},
            'key_management': {'Simple': 1, 'Complex': 2, 'Very Complex': 3},
            'upgrade_cost': {'Low': 1, 'Medium': 2, 'High': 3},
            'implementation_time': {'1-2 weeks': 1, '2-3 weeks': 2, '4-6 weeks': 3, '8-12 weeks': 4}
        }
        
        # Create matrix for heatmap
        schemes = list(complexity_data.keys())
        metrics = ['dependencies', 'code_size', 'key_management', 'upgrade_cost', 'implementation_time']
        
        matrix = []
        for scheme in schemes:
            row = []
            for metric in metrics:
                value = complexity_data[scheme][metric]
                score = complexity_scores[metric].get(value, 1)
                row.append(score)
            matrix.append(row)
        
        # Create heatmap
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Create heatmap
        sns.heatmap(matrix, ax=ax, 
                   xticklabels=['Dependencies', 'Code Size', 'Key Management', 'Upgrade Cost', 'Implementation Time'],
                   yticklabels=schemes,
                   cmap='RdYlGn_r', annot=True, fmt='d', cbar_kws={'label': 'Complexity Level (1=Low, 4=High)'})
        
        ax.set_title('L7: Engineering Complexity Analysis\n'
                    'Implementation Complexity Assessment for Different Encryption Schemes', 
                    fontsize=16, fontweight='bold', pad=20)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Complexity heatmap saved to: {save_path}")
        else:
            plt.show()
        
        return fig

def main():
    """Main function to generate scenario recommendations"""
    recommender = ScenarioRecommendationSystem()
    
    # Generate T7 scenario comparison chart
    t7_chart_path = os.path.join(recommender.results_dir, 'charts', 'scenario_recommendation_t7.png')
    os.makedirs(os.path.dirname(t7_chart_path), exist_ok=True)
    
    fig1 = recommender.generate_scenario_comparison_chart(t7_chart_path)
    
    # Generate L7 complexity heatmap
    l7_chart_path = os.path.join(recommender.results_dir, 'charts', 'engineering_complexity_l7.png')
    fig2 = recommender.generate_complexity_heatmap(l7_chart_path)
    
    # Generate recommendation table
    df = recommender.generate_scenario_recommendation_table()
    table_path = os.path.join(recommender.results_dir, 'scenario_recommendation_table_t7.csv')
    df.to_csv(table_path, index=False, encoding='utf-8')
    print(f"Recommendation table saved to: {table_path}")
    
    print("T7 and L7 charts generated successfully!")

if __name__ == "__main__":
    main()
