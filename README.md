# LoRaWAN Encryption Scheme Evaluation System

A simulation system for evaluating the performance and security of different encryption schemes in LoRaWAN networks.

## 🎯 Core Features

- **Enhanced LoRaWAN Network Simulation**: Complete protocol stack, realistic channel model, ADR mechanism
- **Encryption Scheme Performance Evaluation**: Test performance metrics of various encryption algorithms
- **Security Attack Testing**: Simulate various attack types, evaluate security
- **Comprehensive Recommendation System**: Intelligent recommendations based on performance and security
- **Rich Chart Output**: Performance comparison, security analysis, network statistics and other visualization charts

## 📁 Project Structure

```
lora_encryption_evaluation/
├── main.py                          # Main program entry
├── simulation/
│   ├── enhanced_lora_simulator.py   # Enhanced LoRaWAN simulator
│   ├── network_simulator.py         # Basic network simulator
│   ├── channel_model.py             # Channel model
│   └── lora_protocol.py             # LoRa protocol implementation
├── encryption/
│   ├── schemes.py                   # Basic encryption schemes
│   ├── advanced_schemes.py          # Advanced encryption schemes
│   └── post_quantum_schemes.py      # Post-quantum encryption schemes
├── attacks/
│   ├── attack_simulator.py          # Attack simulator
│   ├── attack_types.py              # Attack type definitions
│   ├── advanced_attacks.py          # Advanced attacks
│   └── improved_attacks.py          # Improved attacks
├── utils/
│   ├── metrics.py                   # Performance metrics calculation
│   └── visualization.py             # Visualization chart generation
├── tests/                           # Test modules
├── results/                         # Results output directory
└── requirements.txt                 # Dependency package list
```

## 🚀 Quick Start

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Evaluation

```bash
python main.py
```

### Generate Charts

```bash
# Run complete evaluation and generate charts
python main.py
```

## 🔧 Core Features

### 1. Enhanced LoRaWAN Simulation

- **Complete Protocol Stack**: Support for Class A/B/C device types
- **Realistic Channel Model**: Path loss, shadowing, SNR calculation
- **ADR Mechanism**: Adaptive Data Rate adjustment
- **Device Management**: Key management, frame counting, device status

### 2. Encryption Scheme Support

- **Traditional Encryption**: AES-128-CTR, ChaCha20-Poly1305
- **Hybrid Encryption**: Hybrid-ECC-AES, Advanced-ECC-AES
- **Post-Quantum Encryption**: Lattice-Based, Kyber, Dilithium, SPHINCS+

### 3. Security Attack Testing

- **Replay Attack**: Replay Attack
- **Man-in-the-Middle Attack**: Man-in-the-Middle Attack
- **Brute Force Attack**: Brute Force Attack
- **Side Channel Attack**: Side Channel Attack
- **Packet Tampering**: Packet Tampering
- **Jamming Attack**: Jamming Attack
- **Key Extraction Attack**: Key Extraction Attack

### 4. Performance Evaluation Metrics

- **Encryption Time**: Encryption/decryption time consumption
- **Transmission Success Rate**: Data packet transmission success rate
- **Energy Consumption Analysis**: Energy consumption evaluation
- **SNR Analysis**: Signal-to-noise ratio statistics
- **ADR Effect**: Adaptive adjustment effect

### 5. Visualization Charts

- **Performance Comparison Charts**: Encryption time, success rate, energy consumption, transmission time comparison
- **Security Analysis Charts**: Security scores, attack success rates, vulnerability scores analysis
- **Network Statistics Charts**: Transmission success rate distribution, device type distribution, network performance metrics
- **Comprehensive Performance Radar Chart**: Multi-dimensional performance metrics comprehensive display
- **Time Series Analysis**: Network performance trends over time
- **HTML Comprehensive Report**: Interactive web report containing all charts

## 📊 Output Results

The system generates detailed evaluation reports including:

- **Network Statistics**: Total packets, success rate, failure rate
- **Device Statistics**: Device type distribution, battery status, spreading factor distribution
- **Encryption Performance**: Performance comparison of various schemes
- **Security Scores**: Security assessment of various schemes
- **Comprehensive Recommendations**: Recommended schemes based on multi-dimensional scoring

### 📈 Chart Output

The system generates the following chart files (saved in `results/charts/` directory):

- `performance_comparison.png` - Performance comparison chart
- `security_analysis.png` - Security analysis chart
- `network_statistics.png` - Network statistics chart
- `radar_chart.png` - Comprehensive performance radar chart
- `timeline_analysis.png` - Time series analysis
- `comprehensive_report.html` - HTML comprehensive report

All charts support English display with professional visual effects and detailed data labels.

## 🎯 Use Cases

- **Academic Research**: LoRaWAN security and performance research
- **Product Development**: Encryption scheme selection and optimization
- **Network Planning**: LoRaWAN network deployment planning
- **Security Assessment**: IoT device security assessment

## 📝 Configuration

You can adjust simulation parameters by modifying the configuration in `main.py`:

```python
config = {
    'simulation': {
        'duration': 300,        # Simulation duration (seconds)
        'num_devices': 10,      # Number of devices
        'num_gateways': 2,      # Number of gateways
        'area_size': (1000, 1000),  # Coverage area
    },
    'security_test': {
        'enabled': True,        # Enable security testing
        'num_test_packets': 10, # Number of test packets
        'attack_attempts': 5    # Number of attack attempts
    }
}
```

## 🤝 Contributing

Welcome to submit Issues and Pull Requests to improve this project.

## 📄 License

This project is licensed under the MIT License.

