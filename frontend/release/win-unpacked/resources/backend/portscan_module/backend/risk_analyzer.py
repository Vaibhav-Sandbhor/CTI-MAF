"""
Risk analyzer — hybrid scoring combining ML predictions with port intelligence
Implements escalation logic where port risk can override ML predictions
"""

from typing import Dict, List, Any
import math

class RiskAnalyzer:
    """Analyze and score network security risk using hybrid approach"""
    
    # CVSS base scores for common vulnerabilities
    CVSS_SCORES = {
        "CRITICAL": 9.0,  # 9.0-10.0
        "HIGH": 7.0,      # 7.0-8.9
        "MEDIUM": 4.0,    # 4.0-6.9
        "LOW": 0.1,       # 0.1-3.9
    }
    
    # Port risk escalation matrix
    PORT_RISK_ESCALATION = {
        "CRITICAL": {"weight": 1.0, "base_score": 95},
        "HIGH": {"weight": 0.7, "base_score": 75},
        "MEDIUM": {"weight": 0.4, "base_score": 50},
        "LOW": {"weight": 0.2, "base_score": 20},
    }
    
    @staticmethod
    def calculate_overall_risk(
        ml_score: float,
        ml_confidence: float,
        port_analysis: List[Dict[str, Any]],
        ports_data: List[Dict[str, Any]],
        dashboard: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate overall system risk using hybrid approach:
        1. Start with ML prediction
        2. Escalate if port intelligence suggests higher risk
        3. Apply confidence-weighted averaging
        
        Returns:
            {
                "overall_risk_score": float (0-100),
                "risk_tier": str ("CRITICAL", "HIGH", "MEDIUM", "LOW"),
                "ml_component": float,
                "port_component": float,
                "confidence": float,
                "escalation_applied": bool,
                "escalation_reason": str,
                "breakdown": dict
            }
        """
        
        # Calculate port-based risk
        port_risk = RiskAnalyzer._calculate_port_risk(port_analysis, ports_data)
        
        # Calculate system attack surface risk
        surface_risk = RiskAnalyzer._calculate_attack_surface_risk(
            dashboard.get("total_ports", 0),
            dashboard.get("critical_port_count", 0),
            dashboard.get("high_port_count", 0)
        )
        
        # Determine if escalation needed
        escalation_applied = False
        escalation_reason = ""
        
        combined_score = ml_score  # Start with ML
        
        # ESCALATION: If port risk is significantly higher, escalate
        if port_risk > ml_score + 25:
            combined_score = (ml_score * 0.4) + (port_risk * 0.6)
            escalation_applied = True
            escalation_reason = f"Port risk ({port_risk:.0f}) significantly exceeds ML prediction ({ml_score:.0f})"
        
        # ESCALATION: Critical ports always escalate
        if dashboard.get("critical_port_count", 0) > 0:
            combined_score = max(combined_score, 85)
            escalation_applied = True
            escalation_reason = "Critical services detected"
        
        # ESCALATION: High attack surface
        if surface_risk > 75:
            combined_score = max(combined_score, surface_risk)
            escalation_applied = True
            escalation_reason = "Large attack surface with multiple open ports"
        
        # Apply confidence weighting
        final_score = RiskAnalyzer._apply_confidence_weighting(
            combined_score,
            ml_confidence,
            escalation_applied
        )
        
        # Determine risk tier
        risk_tier = RiskAnalyzer._score_to_tier(final_score)
        
        return {
            "overall_risk_score": round(final_score, 1),
            "risk_tier": risk_tier,
            "ml_component": round(ml_score, 1),
            "port_component": round(port_risk, 1),
            "surface_risk_component": round(surface_risk, 1),
            "confidence": round(ml_confidence, 1),
            "escalation_applied": escalation_applied,
            "escalation_reason": escalation_reason,
            "breakdown": {
                "ml_weight": 0.5,
                "port_weight": 0.3,
                "surface_weight": 0.2,
                "formula": "0.5*ML + 0.3*PortRisk + 0.2*SurfaceRisk"
            }
        }
    
    @staticmethod
    def _calculate_port_risk(port_analysis: List[Dict[str, Any]], ports_data: List[Dict[str, Any]]) -> float:
        """Calculate risk score based on open ports and their vulnerabilities"""
        if not port_analysis:
            return 0.0
        
        port_scores = []
        
        for port_info in port_analysis:
            risk_level = port_info.get("risk_level", "LOW")
            port_num = port_info.get("port", 0)
            
            # Base score from risk level
            base = RiskAnalyzer.PORT_RISK_ESCALATION.get(risk_level, {}).get("base_score", 20)
            
            # Apply CVSS if available
            cvss = port_info.get("cvss_score", None)
            if cvss and isinstance(cvss, (int, float)):
                cvss_normalized = (cvss / 10.0) * 100  # Normalize 0-10 to 0-100
                base = (base + cvss_normalized) / 2
            
            # Version-specific escalation
            version = None
            for p in ports_data:
                if p.get("port") == port_num:
                    version = p.get("version")
                    break
            
            if version:
                base = RiskAnalyzer._apply_version_risk(base, port_num, version)
            
            port_scores.append(base)
        
        # Weighted average giving more weight to critical services
        if not port_scores:
            return 0.0
        
        weighted_sum = 0
        weight_sum = 0
        
        for i, port_info in enumerate(port_analysis):
            risk_level = port_info.get("risk_level", "LOW")
            weight = RiskAnalyzer.PORT_RISK_ESCALATION.get(risk_level, {}).get("weight", 0.2)
            weighted_sum += port_scores[i] * weight
            weight_sum += weight
        
        return weighted_sum / weight_sum if weight_sum > 0 else sum(port_scores) / len(port_scores)
    
    @staticmethod
    def _apply_version_risk(base_score: float, port: int, version: str) -> float:
        """Apply additional risk based on known vulnerable versions"""
        
        # Common vulnerable version patterns
        vulnerable_patterns = {
            22: {  # SSH
                "OpenSSH 4": 10,
                "OpenSSH 5": 8,
                "OpenSSH 6.0": 5,
            },
            80: {  # HTTP
                "Apache/1": 12,
                "Apache/2.0": 10,
                "Apache/2.2": 8,
            },
            443: {  # HTTPS
                "Apache/1": 8,
                "Apache/2.0": 6,
            },
            3306: {  # MySQL
                "5.0": 10,
                "5.1": 8,
                "5.5": 6,
            },
            445: {  # SMB (Windows)
                "6.0": 15,  # Windows Vista vulnerable to eternal blue
                "6.1": 15,  # Windows 7
            },
        }
        
        if port not in vulnerable_patterns:
            return base_score
        
        version_lower = version.lower() if version else ""
        
        for pattern, score_increase in vulnerable_patterns[port].items():
            if pattern.lower() in version_lower:
                new_score = base_score + score_increase
                return min(new_score, 100)  # Cap at 100
        
        return base_score
    
    @staticmethod
    def _calculate_attack_surface_risk(total_ports: int, critical_count: int, high_count: int) -> float:
        """Calculate risk based on attack surface size"""
        
        # Base risk from port count
        if total_ports == 0:
            return 0.0
        elif total_ports <= 3:
            port_risk = 10.0
        elif total_ports <= 5:
            port_risk = 25.0
        elif total_ports <= 10:
            port_risk = 40.0
        elif total_ports <= 20:
            port_risk = 60.0
        else:
            # Logarithmic scaling for very large surfaces
            port_risk = 60.0 + (10.0 * math.log(total_ports / 20, 10))
        
        # Apply critical/high multiplier
        criticality_factor = 1.0
        if critical_count > 0:
            criticality_factor += (critical_count * 0.4)  # +40% per critical port
        if high_count > 0:
            criticality_factor += (high_count * 0.2)  # +20% per high port
        
        surface_risk = port_risk * criticality_factor
        return min(surface_risk, 100.0)  # Cap at 100
    
    @staticmethod
    def _apply_confidence_weighting(score: float, confidence: float, escalation_applied: bool) -> float:
        """Apply confidence-based adjustments"""
        
        # If escalation was applied, slightly boost confidence
        adjusted_confidence = confidence
        if escalation_applied:
            adjusted_confidence = min(adjusted_confidence + 5, 100)
        
        # Confidence weighting: lower confidence = less extreme scores
        if adjusted_confidence < 60:
            # Pull extreme scores toward middle
            if score > 70:
                score = 70 + ((score - 70) * (adjusted_confidence / 100))
            elif score < 30:
                score = 30 - ((30 - score) * (adjusted_confidence / 100))
        
        return score
    
    @staticmethod
    def _score_to_tier(score: float) -> str:
        """Convert numeric risk score to tier"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    @staticmethod
    def escalate_port_risk_if_needed(
        port_info: Dict[str, Any],
        ports_data: List[Dict[str, Any]]
    ) -> str:
        """
        Escalate port risk level if version/product indicates vulnerability
        Returns updated risk_level
        """
        current_risk = port_info.get("risk_level", "LOW")
        port_num = port_info.get("port", 0)
        
        # Get version info
        version = None
        for p in ports_data:
            if p.get("port") == port_num:
                version = p.get("version")
                break
        
        if not version:
            return current_risk
        
        # Known critical version mappings
        critical_versions = {
            22: ["OpenSSH 4"],  # Very old SSH
            445: ["6.0", "6.1"],  # Windows 6-7 (eternal blue vulnerable)
            23: ["any"],  # Telnet always critical
            21: ["any"],  # FTP always critical
        }
        
        if port_num in critical_versions:
            for crit_version in critical_versions[port_num]:
                if crit_version == "any" or crit_version.lower() in version.lower():
                    return "CRITICAL"
        
        return current_risk
    
    @staticmethod
    def calculate_port_cvss(
        port: int,
        service: str,
        version: str,
        is_internet_exposed: bool
    ) -> float:
        """
        Estimate CVSS score for a port/service combination
        Scale: 0.1 (None) to 10.0 (Critical)
        """
        
        # Base CVSS by service criticality
        base_cvss = {
            22: 6.0,    # SSH - medium base
            21: 7.5,    # FTP - high
            23: 9.8,    # Telnet - critical
            25: 5.4,    # SMTP - medium
            53: 4.3,    # DNS - medium-low
            80: 6.5,    # HTTP - medium
            110: 7.5,   # POP3 - high
            143: 7.5,   # IMAP - high
            389: 6.5,   # LDAP - medium
            443: 5.8,   # HTTPS - medium (depends on config)
            445: 8.8,   # SMB - high (eternal blue, ransomware)
            139: 7.5,   # NetBIOS - high
            1433: 8.6,  # MSSQL - high
            3306: 8.0,  # MySQL - high
            3389: 8.2,  # RDP - high
            5432: 7.8,  # PostgreSQL - high
            5900: 7.5,  # VNC - high
            2049: 9.1,  # NFS - critical (no auth)
        }
        
        cvss = base_cvss.get(port, 5.0)  # Default medium
        
        # Increase if internet-exposed
        if is_internet_exposed:
            cvss = min(cvss + 2.0, 10.0)
        
        # Increase based on version vulnerability
        cvss = min(cvss + RiskAnalyzer._get_version_cvss_increase(port, version), 10.0)
        
        return cvss
    
    @staticmethod
    def _get_version_cvss_increase(port: int, version: str) -> float:
        """Get CVSS increase for known vulnerable versions"""
        if not version:
            return 0.0
        
        version_lower = version.lower()
        
        # Known vulnerable versions
        if port == 445 and ("6.0" in version_lower or "6.1" in version_lower):
            return 1.5  # EternalBlue
        elif port == 22 and "openssh" in version_lower and any(v in version_lower for v in ["4.", "5.0", "5.1"]):
            return 1.0
        elif port == 3306 and any(v in version_lower for v in ["5.0", "5.1"]):
            return 1.2
        
        return 0.0
