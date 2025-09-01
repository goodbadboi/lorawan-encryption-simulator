#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LoRaWAN Attack Type Implementation

Contains simulation implementations of various attacks targeting LoRaWAN networks.
"""

import time
import random
import hashlib
import struct
from typing import Dict, List, Tuple, Optional, Any
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

from encryption.schemes import LoRaWANPacket, get_encryption_scheme


class AttackType(Enum):
    """Attack type enumeration"""
    REPLAY = "replay"
    MAN_IN_THE_MIDDLE = "mitm"
    BRUTE_FORCE = "brute_force"
    SIDE_CHANNEL = "side_channel"
    PACKET_TAMPERING = "packet_tampering"
    JAMMING = "jamming"
    KEY_EXTRACTION = "key_extraction"


@dataclass
class AttackResult:
    """Attack result data class"""
    attack_type: AttackType
    target_scheme: str
    success: bool
    attack_time_ns: int
    attempts: int
    details: Dict[str, Any]
    vulnerability_score: float  # 0.0-1.0, higher means easier to attack


class BaseAttack(ABC):
    """Attack base class"""
    
    def __init__(self, name: str, attack_type: AttackType):
        self.name = name
        self.attack_type = attack_type
        self.max_attempts = 1000
        self.timeout_ns = 10_000_000_000  # 10 second timeout
    
    @abstractmethod
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> AttackResult:
        """Execute attack"""
        pass
    
    def _calculate_vulnerability_score(self, success: bool, attempts: int, time_taken: int) -> float:
        """Calculate vulnerability score"""
        if not success:
            return 0.0
        
        # Calculate score based on attempts and time
        attempt_score = max(0, 1.0 - (attempts / self.max_attempts))
        time_score = max(0, 1.0 - (time_taken / self.timeout_ns))
        
        return (attempt_score + time_score) / 2


class ReplayAttack(BaseAttack):
    """Replay attack"""
    
    def __init__(self):
        super().__init__("Replay Attack", AttackType.REPLAY)
        self.captured_packets: List[LoRaWANPacket] = []
    
    def capture_packet(self, packet: LoRaWANPacket):
        """Capture packet for replay"""
        self.captured_packets.append(packet)
    
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> AttackResult:
        start_time = time.perf_counter_ns()
        attempts = 0
        
        # Check if there are captured packets
        if not self.captured_packets:
            return AttackResult(
                attack_type=self.attack_type,
                target_scheme=scheme_name,
                success=False,
                attack_time_ns=0,
                attempts=0,
                details={"error": "No captured packets available"},
                vulnerability_score=0.0
            )
        
        scheme = get_encryption_scheme(scheme_name)
        
        # 模拟MAC层重放检测逻辑
        def test_replay_attack(replay_packet: LoRaWANPacket, current_packet: LoRaWANPacket) -> bool:
            """测试重放攻击是否成功 - 基于FCnt单调性和MIC验证"""
            
            # 1. FCnt单调性检查 (LoRaWAN要求FCnt严格递增)
            if replay_packet.fcnt <= current_packet.fcnt:
                return False  # FCnt不单调，重放失败
            
            # 2. MIC验证 (所有方案都应该验证MIC/签名)
            # 假设所有方案都正确实现了MIC验证
            mic_valid = True  # 正常情况下MIC应该有效
            
            # 3. 时间窗口检查 (可选，防止延迟重放)
            # 这里简化处理，假设时间窗口检查通过
            
            return mic_valid
        
        # Try to replay each captured packet
        for captured_packet in self.captured_packets:
            attempts += 1
            
            # 使用统一的MAC层重放检测逻辑
            replay_success = test_replay_attack(captured_packet, packet)
            
            if replay_success:
                end_time = time.perf_counter_ns()
                return AttackResult(
                    attack_type=self.attack_type,
                    target_scheme=scheme_name,
                    success=True,
                    attack_time_ns=end_time - start_time,
                    attempts=attempts,
                    details={
                        "replayed_packet_fcnt": captured_packet.fcnt,
                        "current_packet_fcnt": packet.fcnt,
                        "accepted": True,
                        "reason": "FCnt monotonicity check passed"
                    },
                    vulnerability_score=self._calculate_vulnerability_score(True, attempts, end_time - start_time)
                )
            
            if attempts >= self.max_attempts:
                break
        
        end_time = time.perf_counter_ns()
        return AttackResult(
            attack_type=self.attack_type,
            target_scheme=scheme_name,
            success=False,
            attack_time_ns=end_time - start_time,
            attempts=attempts,
            details={
                "error": "Replay attack failed - FCnt monotonicity or MIC validation failed",
                "tested_packets": len(self.captured_packets)
            },
            vulnerability_score=0.0
        )


class ManInTheMiddleAttack(BaseAttack):
    """Man-in-the-middle attack"""
    
    def __init__(self):
        super().__init__("Man-in-the-middle Attack", AttackType.MAN_IN_THE_MIDDLE)
    
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> AttackResult:
        start_time = time.perf_counter_ns()
        attempts = 0
        
        # Simulate some successful man-in-the-middle attacks (based on scheme characteristics)
        success_probability = {
            "AES-128-CTR": 0.08,  # 8% success rate
            "ChaCha20-Poly1305": 0.05,  # 5% success rate
            "Hybrid-ECC-AES": 0.03,  # 3% success rate
            "Advanced-ECC-AES": 0.02,  # 2% success rate
            "ECC-SC-MIC": 0.06   # 6% success rate
        }
        
        # Try different modification strategies
        modification_strategies = ["payload", "fcnt", "dev_eui"]
        
        for strategy in modification_strategies:
            attempts += 1
            
            # Simulate success based on probability
            if random.random() < success_probability.get(scheme_name, 0.04):
                end_time = time.perf_counter_ns()
                return AttackResult(
                    attack_type=self.attack_type,
                    target_scheme=scheme_name,
                    success=True,
                    attack_time_ns=end_time - start_time,
                    attempts=attempts,
                    details={
                        "modification": strategy,
                        "accepted": True,
                        "simulated": True
                    },
                    vulnerability_score=self._calculate_vulnerability_score(True, attempts, end_time - start_time)
                )
            
            if attempts >= self.max_attempts:
                break
        
        end_time = time.perf_counter_ns()
        return AttackResult(
            attack_type=self.attack_type,
            target_scheme=scheme_name,
            success=False,
            attack_time_ns=end_time - start_time,
            attempts=attempts,
            details={"error": "MITM attack failed"},
            vulnerability_score=0.0
        )


class BruteForceAttack(BaseAttack):
    """Improved brute force attack (using MIC as oracle)"""
    
    def __init__(self):
        super().__init__("Improved Brute Force Attack", AttackType.BRUTE_FORCE)
        self.max_attempts = 1000
    
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> AttackResult:
        start_time = time.perf_counter_ns()
        attempts = 0
        
        weak_keys = [
            b'\x00' * 16,
            b'\xFF' * 16,
            b'password123456',
            b'admin123456789',
            b'1234567890123456',
            b'abcdefghijklmnop',
        ]
        if hasattr(packet, 'dev_eui'):
            weak_keys.extend([
                packet.dev_eui + b'\x00' * 8,
                packet.dev_eui[:8] + packet.dev_eui[:8],
                hashlib.md5(packet.dev_eui).digest(),
            ])
        if hasattr(packet, 'fcnt'):
            weak_keys.extend([
                packet.fcnt.to_bytes(16, 'big'),
                packet.fcnt.to_bytes(16, 'little'),
                hashlib.md5(packet.fcnt.to_bytes(4, 'big')).digest(),
            ])
        weak_keys.extend(self._load_password_dictionary())
        for i in range(max(0, self.max_attempts - len(weak_keys))):
            weak_keys.append(get_random_bytes(16))
        
        scheme = get_encryption_scheme(scheme_name)
        for test_key in weak_keys:
            attempts += 1
            try:
                # Use verify_mic as success oracle to avoid false positives
                if scheme.verify_mic(packet, test_key):
                    end_time = time.perf_counter_ns()
                    return AttackResult(
                        attack_type=self.attack_type,
                        target_scheme=scheme_name,
                        success=True,
                        attack_time_ns=end_time - start_time,
                        attempts=attempts,
                        details={"key_found": test_key.hex()},
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
            details={"error": "Brute force failed (no MIC match)"},
            vulnerability_score=0.0
        )

    def _load_password_dictionary(self) -> List[bytes]:
        common_passwords = [
            b'password', b'123456', b'admin', b'root', b'user',
            b'guest', b'test', b'default', b'secret', b'private',
            b'key', b'crypto', b'secure', b'encrypt', b'decrypt'
        ]
        dictionary_keys = []
        for pwd in common_passwords:
            if len(pwd) < 16:
                key = pwd + b'\x00' * (16 - len(pwd))
            else:
                key = pwd[:16]
            dictionary_keys.append(key)
        return dictionary_keys


class SideChannelAttack(BaseAttack):
    """Side channel attack (correlation detection)"""
    
    def __init__(self):
        super().__init__("Side Channel Attack", AttackType.SIDE_CHANNEL)
    
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> AttackResult:
        start_time = time.perf_counter_ns()
        attempts = 0
        scheme = get_encryption_scheme(scheme_name)
        
        # Multiple rounds of sampling
        test_payloads = [b'A' * n for n in (16, 32, 64, 96, 128, 192, 256)]
        lengths, times = [], []
        for payload in test_payloads:
            attempts += 1
            test_packet = LoRaWANPacket(dev_eui=packet.dev_eui, payload=payload, fcnt=packet.fcnt)
            try:
                _, encrypt_time = scheme.encrypt(test_packet, key)
                lengths.append(len(payload))
                times.append(encrypt_time)
            except Exception:
                continue
        
        detected = False
        details = {"samples": len(times)}
        if len(times) >= 4:
            # Calculate Pearson correlation coefficient
            avg_x = sum(lengths) / len(lengths)
            avg_y = sum(times) / len(times)
            cov = sum((x - avg_x) * (y - avg_y) for x, y in zip(lengths, times))
            var_x = sum((x - avg_x) ** 2 for x in lengths) or 1
            var_y = sum((y - avg_y) ** 2 for y in times) or 1
            corr = cov / (var_x ** 0.5 * var_y ** 0.5)
            details.update({"corr": corr})
            detected = corr > 0.8 and sum(1 for i in range(1, len(times)) if times[i] >= times[i-1]) >= len(times) - 1
        
        end_time = time.perf_counter_ns()
        if detected:
            return AttackResult(
                attack_type=self.attack_type,
                target_scheme=scheme_name,
                success=True,
                attack_time_ns=end_time - start_time,
                attempts=attempts,
                details=details,
                vulnerability_score=self._calculate_vulnerability_score(True, attempts, end_time - start_time)
            )
        return AttackResult(
            attack_type=self.attack_type,
            target_scheme=scheme_name,
            success=False,
            attack_time_ns=end_time - start_time,
            attempts=attempts,
            details={"error": "No strong timing correlation", **details},
            vulnerability_score=0.0
        )


class PacketTamperingAttack(BaseAttack):
    """Packet tampering attack (using MIC/AEAD as criterion)"""
    
    def __init__(self):
        super().__init__("Packet Tampering Attack", AttackType.PACKET_TAMPERING)
    
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> AttackResult:
        start_time = time.perf_counter_ns()
        attempts = 0
        scheme = get_encryption_scheme(scheme_name)
        
        def t_payload(p): setattr(p, 'encrypted_payload', (p.encrypted_payload or b'') + b'TAMPERED')
        def t_mic(p): setattr(p, 'mic', get_random_bytes(4))
        def t_nonce(p): setattr(p, 'nonce', get_random_bytes(12))
        def t_dev_eui(p): setattr(p, 'dev_eui', get_random_bytes(8))
        def t_fcnt(p): setattr(p, 'fcnt', p.fcnt + 100)
        tampering_strategies = [t_payload, t_mic, t_nonce, t_dev_eui, t_fcnt]
        
        for strategy in tampering_strategies:
            attempts += 1
            try:
                tampered_packet = LoRaWANPacket(dev_eui=packet.dev_eui, payload=packet.payload, fcnt=packet.fcnt)
                tampered_packet.encrypted_payload = getattr(packet, 'encrypted_payload', None)
                tampered_packet.mic = getattr(packet, 'mic', None)
                tampered_packet.nonce = getattr(packet, 'nonce', None)
                strategy(tampered_packet)
                
                # Success condition: bypass verify_mic
                if scheme.verify_mic(tampered_packet, key):
                    end_time = time.perf_counter_ns()
                    return AttackResult(
                        attack_type=self.attack_type,
                        target_scheme=scheme_name,
                        success=True,
                        attack_time_ns=end_time - start_time,
                        attempts=attempts,
                        details={"bypassed_mic": True, "strategy": strategy.__name__},
                        vulnerability_score=self._calculate_vulnerability_score(True, attempts, end_time - start_time)
                    )
            except Exception:
                continue
            if attempts >= self.max_attempts:
                break
        
        end_time = time.perf_counter_ns()
        return AttackResult(
            attack_type=self.attack_type,
            target_scheme=scheme_name,
            success=False,
            attack_time_ns=end_time - start_time,
            attempts=attempts,
            details={"error": "Tampering failed (MIC/AEAD blocked)"},
            vulnerability_score=0.0
        )


class JammingAttack(BaseAttack):
    """Jamming attack (link layer packet loss model)"""
    
    def __init__(self):
        super().__init__("Jamming Attack", AttackType.JAMMING)
        # 物理参数配置
        self.CAPTURE_TH_DB = 6.0           # LoRa捕获门限 (dB)
        self.time_constant_tau = 0.65      # 时间常数 (s)
        self.snr_reference = 8.0           # SNR参考值 (dB)
        self.signal_power_range = (8, 16)  # 信号功率范围 (dBm)
        self.jammer_power_range = (6, 20)  # 干扰器功率范围 (dBm) - 覆盖信号功率±8dB
        self.overlap_range = (0.35, 0.65)  # 重叠比例范围
        
        # LoRa ToA计算参数
        self.PHY_MAX = 222  # LoRaWAN SF7/BW125最大PHY载荷 (字节)
        self.OVERHEAD = 13  # 协议开销 (字节)
        self.duty_cycle_range = (0.15, 0.30)  # 占空比范围
    
    def _calculate_jamming_success_probability(self, packet: LoRaWANPacket, scheme_name: str) -> Dict[str, float]:
        """计算基于物理量的干扰成功率"""
        import math
        
        # 1. 重叠比例概率 (p_overlap)
        overlap_ratio = random.uniform(*self.overlap_range)
        # 使用S型函数平滑重叠比例
        p_overlap = 1 / (1 + math.exp(-10 * (overlap_ratio - 0.5)))
        
        # 2. 捕获裕度概率 (p_capture)
        # 统一定义: delta_db = P_jam - P_sig (>0表示干扰更强)
        signal_power = random.uniform(*self.signal_power_range)
        jammer_power = random.uniform(*self.jammer_power_range)
        delta_db = jammer_power - signal_power  # 干扰-信号功率差
        
        # 使用LoRa捕获门限: 当delta_db > CAPTURE_TH_DB时，干扰成功概率增大
        k = 2.0  # 平滑因子
        p_capture = 1.0 / (1.0 + math.exp(-(delta_db - self.CAPTURE_TH_DB) / k))
        
        # 3. 传输时间概率 (p_time) - 真实LoRa ToA计算
        # 基于真实LoRa ToA公式计算分片总时长
        toa = getattr(packet, 'time_on_air', 0.1)  # 默认0.1s
        if hasattr(packet, 'payload') and packet.payload:
            payload_size = len(packet.payload)
            # 使用真实LoRa ToA计算
            toa = self._calculate_lora_toa_total(payload_size, scheme_name)
        
        # 使用反应式干扰模型：τ=0.65s，适合检测前导就开打的场景
        p_time = 1 - math.exp(-toa / self.time_constant_tau)
        
        # 4. 解调失败概率 (p_demod_fail) - 基于SINR
        # 计算线性功率
        Ps_lin = 10**(signal_power / 10)  # mW
        Pj_lin = 10**(jammer_power / 10)  # mW
        
        # 噪声功率计算 (热噪声公式)
        # Pn_dBm = -174 + 10*log10(BW_Hz) + NF
        # 对125kHz, NF=6dB: -174 + 10*log10(125000) + 6 ≈ -117.0 dBm
        Pn_dbm = -174 + 10*math.log10(125000) + 6  # dBm
        Pn_lin = 10**(Pn_dbm / 10) / 1000  # 转换为mW
        
        # 计算SINR (含干扰)
        sinr_lin = Ps_lin / (Pj_lin + Pn_lin)
        sinr_db = 10 * math.log10(sinr_lin)
        
        # LoRa解调门限 (基于SF/BW/CR)
        # SF=7, BW=125kHz, CR=4/5 的解调门限约为 -7.5 dB
        SNR_th = -7.5  # dB (LoRa解调门限，负值表示门限)
        k_snr = 1.5    # 平滑因子 (dB)
        p_demod_fail = 1.0 / (1.0 + math.exp(-(SNR_th - sinr_db) / k_snr))
        
        # 5. 物理层失败概率 (p_phy_fail) - 去重计数
        # p_capture: 前导/同步阶段被压制/被夺锁的概率
        # p_demod_fail: 载荷解调因SINR不足失败的概率
        # 两者并联失败
        p_phy_fail = 1 - (1 - p_capture) * (1 - p_demod_fail)
        
        # 6. 最终干扰成功率
        p_jam = p_overlap * p_time * p_phy_fail
        
        return {
            'p_overlap': p_overlap,
            'p_capture': p_capture, 
            'p_time': p_time,
            'p_demod_fail': p_demod_fail,
            'p_phy_fail': p_phy_fail,
            'p_jam': p_jam,
            'overlap_ratio': overlap_ratio,
            'delta_db': delta_db,
            'toa': toa,
            'sinr_db': sinr_db,
            'jammer_power': jammer_power,
            'signal_power': signal_power,
            'CAPTURE_TH_DB': self.CAPTURE_TH_DB,
            'SNR_th': SNR_th,
            'Pn_dbm': Pn_dbm  # 噪声功率 (dBm)
        }
    
    def _calculate_lora_toa_single_frame(self, payload_bytes, sf=7, bw=125000, cr_val=1, 
                                        preamble=8, crc=1, header_explicit=True):
        """
        计算单帧LoRa ToA (Semtech标准公式)
        """
        import math
        
        H = 0 if header_explicit else 1
        DE = 1 if (bw == 125000 and sf >= 11) else 0
        
        # 符号时长
        Ts = (2**sf) / bw
        
        # 载荷符号数计算
        num = 8*payload_bytes - 4*sf + 28 + 16*crc - 20*H
        den = 4*(sf - 2*DE)
        payload_sym = 8 + max(math.ceil(num/den) * (cr_val + 4), 0)
        
        # 总ToA
        total_sym = preamble + 4.25 + payload_sym
        return total_sym * Ts  # 秒
    
    def _calculate_lora_toa_total(self, total_bytes, scheme_name):
        """
        计算分片总ToA - 确保payload_size_bytes只表示应用层原始字节
        """
        # 根据方案类型调整总字节数（应用层原始数据）
        if scheme_name in ["Kyber", "Dilithium", "SPHINCS+"]:
            # PQC方案有更大的数据量
            if scheme_name == "Dilithium":
                # Dilithium签名约2700字节
                total_bytes = max(total_bytes, 2700)
            elif scheme_name == "SPHINCS+":
                # SPHINCS+签名约41000字节
                total_bytes = max(total_bytes, 41000)
            else:  # Kyber
                # Kyber密钥交换约1632字节
                total_bytes = max(total_bytes, 1632)
        else:
            # 传统方案保持原有大小
            total_bytes = max(total_bytes, 50)
        
        # 边界扫频测试：512B测试用例
        if total_bytes == 512:
            print(f"🔧 Boundary Test - {scheme_name}: 512B payload for ToA validation")
        
        # 分片计算 - 确保不重复叠加开销
        app_left = total_bytes  # 应用层原始字节
        toa_sum = 0.0
        n_frags = 0
        pl_sizes = []  # 记录每帧的PL大小
        
        while app_left > 0:
            app_this = min(self.PHY_MAX - self.OVERHEAD, app_left)  # 应用层字节
            pl_i = self.OVERHEAD + app_this  # PHY层字节 = 开销 + 应用数据
            toa_frame = self._calculate_lora_toa_single_frame(pl_i)
            toa_sum += toa_frame
            pl_sizes.append(pl_i)
            app_left -= app_this
            n_frags += 1
        
        # 调试信息
        overhead_total = n_frags * self.OVERHEAD
        pl_min, pl_mean, pl_max = min(pl_sizes), sum(pl_sizes)/len(pl_sizes), max(pl_sizes)
        toa_frame_mean = toa_sum / n_frags
        
        print(f"🔧 ToA Debug - {scheme_name}:")
        print(f"   app_bytes_total: {total_bytes}B, n_frags: {n_frags}, overhead_total: {overhead_total}B")
        print(f"   PL_i range: {pl_min:.1f}-{pl_max:.1f}B (mean: {pl_mean:.1f}B)")
        print(f"   ToA_frame_mean: {toa_frame_mean:.3f}s, ToA_total: {toa_sum:.3f}s")
        
        return toa_sum
    
    def _calculate_per_after(self, per_before: float, jam_success: bool, prob_components: Dict[str, float]) -> float:
        """计算干扰后的包错误率"""
        if not jam_success:
            return per_before  # 干扰失败，保持原错误率
        
        # 干扰成功时的包错误率计算
        p_symbol_damage = prob_components['p_capture'] * prob_components['p_overlap']
        per_after = 1 - (1 - per_before) * (1 - p_symbol_damage)
        
        return per_after
    
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> AttackResult:
        start_time = time.perf_counter_ns()
        attempts = 0
        
        # 计算基于物理量的干扰成功率
        prob_components = self._calculate_jamming_success_probability(packet, scheme_name)
        success_prob = prob_components['p_jam']
        
        # 打印详细的概率分量（调试信息）
        print(f"🔧 Jamming Debug - {scheme_name}:")
        print(f"   SF=7, BW=125kHz, CR=4/5, SNR_th={prob_components['SNR_th']:.1f}dB, τ={self.time_constant_tau:.2f}s, Pn={prob_components['Pn_dbm']:.1f}dBm")
        print(f"   Ps: {prob_components['signal_power']:.1f}dBm, Pj: {prob_components['jammer_power']:.1f}dBm")
        print(f"   delta_db: {prob_components['delta_db']:.1f}dB, CAPTURE_TH_DB: {prob_components['CAPTURE_TH_DB']:.1f}dB")
        print(f"   p_overlap: {prob_components['p_overlap']:.3f} (overlap: {prob_components['overlap_ratio']:.3f})")
        print(f"   p_capture: {prob_components['p_capture']:.3f} (delta_db: {prob_components['delta_db']:.1f}dB)")
        print(f"   p_time: {prob_components['p_time']:.3f} (ToA: {prob_components['toa']:.3f}s)")
        print(f"   p_demod_fail: {prob_components['p_demod_fail']:.3f} (SINR: {prob_components['sinr_db']:.1f}dB)")
        print(f"   p_phy_fail: {prob_components['p_phy_fail']:.3f} (capture+demod)")
        print(f"   p_jam: {success_prob:.3f}")
        
        # 尝试不同的干扰级别
        jamming_levels = [0.2, 0.4, 0.6, 0.8]
        for level in jamming_levels:
            attempts += 1
            
            # 基于物理量模拟成功
            if random.random() < success_prob:
                # 确定干扰结果类型
                per_before = 0.01  # 干扰前包错误率
                per_after = self._calculate_per_after(per_before, True, prob_components)
                
                # 判断是丢包还是延迟
                if per_after > 0.5:  # 高错误率判定为丢包
                    result_type = "drop"
                    delay_time = 0
                else:  # 低错误率判定为延迟
                    result_type = "delay"
                    delay_time = prob_components['toa'] * random.uniform(0.2, 0.5)  # 延迟时间
                
                end_time = time.perf_counter_ns()
                return AttackResult(
                    attack_type=self.attack_type,
                    target_scheme=scheme_name,
                    success=True,
                    attack_time_ns=end_time - start_time,
                    attempts=attempts,
                    details={
                        "result_type": result_type,
                        "jamming_level": level,
                        "per_before": per_before,
                        "per_after": per_after,
                        "delay_time": delay_time,
                        "prob_components": prob_components,
                        "simulated": True
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
                "error": "No packet drop",
                "per_before": 0.01,
                "per_after": 0.01,
                "prob_components": prob_components
            },
            vulnerability_score=0.0
        )


class KeyExtractionAttack(BaseAttack):
    """Key extraction attack (only succeeds when real weaknesses are detected: nonce reuse/counter reuse)"""
    
    def __init__(self):
        super().__init__("Key Extraction Attack", AttackType.KEY_EXTRACTION)
        self._seen_nonces: Dict[tuple, bytes] = {}
    
    def execute(self, packet: LoRaWANPacket, scheme_name: str, key: bytes) -> AttackResult:
        start_time = time.perf_counter_ns()
        attempts = 1
        
        scheme = get_encryption_scheme(scheme_name)
        details = {}
        success = False
        
        # Only use nonce reuse as success condition
        nonce = getattr(packet, 'nonce', None)
        if nonce:
            key_id = (scheme_name, packet.dev_eui)
            prev = self._seen_nonces.get(key_id)
            if prev is not None and prev == nonce:
                success = True
                details["nonce_reuse"] = True
            else:
                self._seen_nonces[key_id] = nonce
        
        end_time = time.perf_counter_ns()
        if success:
            return AttackResult(
                attack_type=self.attack_type,
                target_scheme=scheme_name,
                success=True,
                attack_time_ns=end_time - start_time,
                attempts=attempts,
                details=details or {"nonce_reuse": True},
                vulnerability_score=self._calculate_vulnerability_score(True, attempts, end_time - start_time)
            )
        return AttackResult(
            attack_type=self.attack_type,
            target_scheme=scheme_name,
            success=False,
            attack_time_ns=end_time - start_time,
            attempts=attempts,
            details={"error": "No nonce/CTR reuse observed"},
            vulnerability_score=0.0
        )


def get_attack_instance(attack_type: AttackType) -> BaseAttack:
    """Get attack instance by attack type"""
    attacks = {
        AttackType.REPLAY: ReplayAttack(),
        AttackType.MAN_IN_THE_MIDDLE: ManInTheMiddleAttack(),
        AttackType.BRUTE_FORCE: BruteForceAttack(),
        AttackType.SIDE_CHANNEL: SideChannelAttack(),
        AttackType.PACKET_TAMPERING: PacketTamperingAttack(),
        AttackType.JAMMING: JammingAttack(),
        AttackType.KEY_EXTRACTION: KeyExtractionAttack()
    }
    return attacks[attack_type]