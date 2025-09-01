#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pareto Frontier Analysis for LoRaWAN Encryption Schemes
Based on actual project data for Chapter 5.2.4
"""

import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from typing import Dict, List, Tuple
import json

# Set font for Chinese characters
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'SimHei']
plt.rcParams['axes.unicode_minus'] = False

class ParetoFrontierAnalyzer:
    """Pareto Frontier Analysis for encryption schemes"""
    
    def __init__(self, results_dir: str = "results"):
        self.results_dir = results_dir
        self.schemes_data = {}
        self.pareto_frontier = []
        
    def load_project_data(self):
        """Load actual project data from JSON files"""
        # Load simulation data
        sim_report_path = os.path.join(self.results_dir, 'simulation_report.json')
        security_report_path = os.path.join(self.results_dir, 'security_report.json')
        
        with open(sim_report_path, 'r', encoding='utf-8') as f:
            sim_data = json.load(f)
        
        with open(security_report_path, 'r', encoding='utf-8') as f:
            security_data = json.load(f)
        
        # Extract performance data
        performance_data = sim_data['encryption_performance']
        
        # Extract security data
        security_rankings = {item['scheme_name']: item for item in security_data['scheme_rankings']}
        
        # Combine data
        for scheme_name, perf_data in performance_data.items():
            if scheme_name in security_rankings:
                self.schemes_data[scheme_name] = {
                    'energy_consumption': perf_data['average_energy'],  # nJ
                    'transmission_time': perf_data['average_transmission_time'],  # s
                    'success_rate': perf_data['success_rate'],
                    'overhead': perf_data['average_overhead'],  # bytes
                    'attack_success_rate': security_rankings[scheme_name]['success_rate'],
                    'security_score': security_rankings[scheme_name]['security_score']
                }
    
    def calculate_throughput_per_energy(self, scheme_name: str) -> float:
        """Calculate throughput per energy (bytes/μJ)"""
        data = self.schemes_data[scheme_name]
        payload_size = 40  # bytes (from project configuration)
        energy_μj = data['energy_consumption'] / 1000  # convert nJ to μJ
        
        # Throughput = payload_size / transmission_time
        throughput = payload_size / data['transmission_time']  # bytes/s
        
        # Throughput per energy = throughput / energy
        return throughput / energy_μj
    
    def calculate_pareto_frontier(self) -> List[str]:
        """Calculate Pareto frontier points"""
        frontier_points = []
        
        # Sort schemes by attack success rate (x-axis)
        sorted_schemes = sorted(self.schemes_data.items(), 
                              key=lambda x: x[1]['attack_success_rate'])
        
        # Find Pareto optimal points
        max_throughput_per_energy = 0
        for scheme_name, data in sorted_schemes:
            throughput_per_energy = self.calculate_throughput_per_energy(scheme_name)
            
            if throughput_per_energy > max_throughput_per_energy:
                max_throughput_per_energy = throughput_per_energy
                frontier_points.append(scheme_name)
        
        self.pareto_frontier = frontier_points
        return frontier_points
    
    def generate_pareto_chart(self, save_path: str = None):
        """Generate Pareto frontier chart"""
        if not self.schemes_data:
            self.load_project_data()
        
        # Calculate Pareto frontier
        self.calculate_pareto_frontier()
        
        # Prepare data for plotting
        x_values = []  # Attack success rate
        y_values = []  # Throughput per energy
        scheme_names = []
        colors = []
        
        # Color scheme
        color_map = {
            'AES-128-GCM': '#1f77b4',           # Blue
            'ChaCha20-Poly1305': '#ff7f0e',     # Orange
            'Hybrid-ECC-AES': '#2ca02c',        # Green
            'Advanced-ECC-AES': '#d62728',      # Red
            'ChaCha20-Poly1305-Lite': '#9467bd' # Purple
        }
        
        for scheme_name, data in self.schemes_data.items():
            x_values.append(data['attack_success_rate'])
            y_values.append(self.calculate_throughput_per_energy(scheme_name))
            scheme_names.append(scheme_name)
            colors.append(color_map.get(scheme_name, '#7f7f7f'))
        
        # Create figure
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Plot all points
        scatter = ax.scatter(x_values, y_values, c=colors, s=200, alpha=0.7, 
                           edgecolors='black', linewidth=1.5)
        
        # Add labels for each point
        for i, scheme_name in enumerate(scheme_names):
            ax.annotate(scheme_name, 
                       (x_values[i], y_values[i]),
                       xytext=(5, 5), textcoords='offset points',
                       fontsize=10, fontweight='bold',
                       bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.8))
        
        # Plot Pareto frontier line
        if len(self.pareto_frontier) >= 2:
            frontier_x = [self.schemes_data[name]['attack_success_rate'] 
                         for name in self.pareto_frontier]
            frontier_y = [self.calculate_throughput_per_energy(name) 
                         for name in self.pareto_frontier]
            
            # Sort by x-axis for proper line drawing
            frontier_points = sorted(zip(frontier_x, frontier_y))
            frontier_x_sorted, frontier_y_sorted = zip(*frontier_points)
            
            ax.plot(frontier_x_sorted, frontier_y_sorted, '--', color='red', 
                   linewidth=3, alpha=0.8, label='Pareto Frontier')
        
        # Customize axes
        ax.set_xlabel('Attack Success Rate (lower is better)', fontsize=14, fontweight='bold')
        ax.set_ylabel('Throughput per Energy (bytes/μJ, higher is better)', 
                     fontsize=14, fontweight='bold')
        ax.set_title('F12: Pareto Frontier — Performance/Energy vs Attack Success Rate\n'
                    'Based on LoRaWAN Encryption Scheme Evaluation', 
                    fontsize=16, fontweight='bold', pad=20)
        
        # Add grid
        ax.grid(True, alpha=0.3)
        
        # Add legend
        legend_elements = []
        for scheme_name, color in color_map.items():
            if scheme_name in self.schemes_data:
                legend_elements.append(mpatches.Patch(color=color, label=scheme_name))
        
        ax.legend(handles=legend_elements, loc='upper right', fontsize=12)
        
        # Add Pareto frontier legend
        if len(self.pareto_frontier) >= 2:
            ax.plot([], [], '--', color='red', linewidth=3, label='Pareto Frontier')
            ax.legend(loc='upper right', fontsize=12)
        
        # Add text box with key insights
        insights_text = f"""Key Insights:
• AES-128-GCM: Best balance (Security: {self.schemes_data['AES-128-GCM']['security_score']:.3f})
• ChaCha20-Poly1305-Lite: Highest efficiency
• Advanced-ECC-AES: Highest security, lowest efficiency
• Pareto Frontier: Optimal trade-off boundary"""
        
        ax.text(0.02, 0.98, insights_text, transform=ax.transAxes, fontsize=11,
               verticalalignment='top', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
        
        # Adjust layout
        plt.tight_layout()
        
        # Save or show
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"Pareto frontier chart saved to: {save_path}")
        else:
            plt.show()
        
        return fig
    
    def generate_detailed_table(self) -> str:
        """Generate detailed data table for the paper"""
        if not self.schemes_data:
            self.load_project_data()
        
        table_data = []
        for scheme_name, data in self.schemes_data.items():
            throughput_per_energy = self.calculate_throughput_per_energy(scheme_name)
            table_data.append({
                'Scheme': scheme_name,
                'Attack_Success_Rate': f"{data['attack_success_rate']:.3f}",
                'Throughput_per_Energy': f"{throughput_per_energy:.2f}",
                'Energy_Consumption': f"{data['energy_consumption']/1e6:.2f}",
                'Transmission_Time': f"{data['transmission_time']:.3f}",
                'Security_Score': f"{data['security_score']:.3f}",
                'Pareto_Optimal': 'Yes' if scheme_name in self.pareto_frontier else 'No'
            })
        
        # Sort by attack success rate
        table_data.sort(key=lambda x: float(x['Attack_Success_Rate']))
        
        # Generate markdown table
        markdown_table = "| Scheme | Attack Success Rate | Throughput/Energy (bytes/μJ) | Energy (mJ) | ToA (s) | Security Score | Pareto Optimal |\n"
        markdown_table += "|--------|-------------------|------------------------------|-------------|---------|----------------|----------------|\n"
        
        for row in table_data:
            markdown_table += f"| {row['Scheme']} | {row['Attack_Success_Rate']} | {row['Throughput_per_Energy']} | {row['Energy_Consumption']} | {row['Transmission_Time']} | {row['Security_Score']} | {row['Pareto_Optimal']} |\n"
        
        return markdown_table

def main():
    """Main function to generate Pareto frontier analysis"""
    analyzer = ParetoFrontierAnalyzer()
    
    # Generate chart
    chart_path = os.path.join(analyzer.results_dir, 'charts', 'pareto_frontier_f12.png')
    os.makedirs(os.path.dirname(chart_path), exist_ok=True)
    
    fig = analyzer.generate_pareto_chart(chart_path)
    
    # Generate detailed table
    table = analyzer.generate_detailed_table()
    
    # Save table to file
    table_path = os.path.join(analyzer.results_dir, 'pareto_frontier_table.md')
    with open(table_path, 'w', encoding='utf-8') as f:
        f.write("# F12: Pareto Frontier Data Table\n\n")
        f.write("Detailed data for Chapter 5.2.4 analysis\n\n")
        f.write(table)
    
    print(f"Detailed table saved to: {table_path}")
    
    # Print summary
    print("\n" + "="*60)
    print("PARETO FRONTIER ANALYSIS SUMMARY")
    print("="*60)
    print(f"Pareto optimal schemes: {', '.join(analyzer.pareto_frontier)}")
    print(f"Total schemes analyzed: {len(analyzer.schemes_data)}")
    print("="*60)

if __name__ == "__main__":
    main()
