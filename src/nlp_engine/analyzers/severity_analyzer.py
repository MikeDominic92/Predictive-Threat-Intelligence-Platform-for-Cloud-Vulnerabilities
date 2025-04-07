"""
Severity Analyzer Module.

This module analyzes the severity and impact of identified threats
from unstructured text data using keyword analysis and context.
"""

import re
from typing import List, Dict, Any, Tuple, Optional, Set
from dataclasses import dataclass

from ..extractors.entity_extractor import ExtractedEntity

@dataclass
class SeverityAssessment:
    """Represents a severity assessment for an entity or text."""
    entity: Optional[ExtractedEntity] = None
    severity_score: float = 0.0  # 0.0 to 1.0
    severity_level: str = "unknown"  # unknown, low, medium, high, critical
    confidence: float = 0.0
    evidence: List[str] = None
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "severity_score": self.severity_score,
            "severity_level": self.severity_level,
            "confidence": self.confidence,
            "evidence": self.evidence
        }
        
        if self.entity:
            result["entity"] = self.entity.to_dict()
            
        return result


class SeverityAnalyzer:
    """
    Analyzes the severity and potential impact of identified threats.
    
    This class uses keyword analysis, contextual clues, and threat
    intelligence sources to determine how severe a threat might be.
    """
    
    def __init__(self):
        """Initialize the severity analyzer with keyword dictionaries."""
        # Severity keywords with weights
        self.severity_keywords = {
            "critical": {
                "active exploitation": 1.0,
                "zero-day": 1.0,
                "zero day": 1.0,
                "widespread": 0.9,
                "ransomware": 0.9,
                "data breach": 0.9,
                "massive": 0.8,
                "critical vulnerability": 1.0,
                "critical impact": 1.0,
                "significant damage": 0.9,
                "national security": 0.9,
                "emergency patch": 0.9,
                "immediate action": 0.8
            },
            "high": {
                "high impact": 0.8,
                "high risk": 0.8,
                "exploit available": 0.8,
                "actively targeting": 0.7,
                "vulnerability": 0.6,
                "serious": 0.7,
                "important patch": 0.7,
                "data loss": 0.7,
                "privilege escalation": 0.7,
                "remote code execution": 0.7,
                "unauthorized access": 0.7
            },
            "medium": {
                "moderate": 0.6,
                "potential impact": 0.5,
                "could affect": 0.5,
                "may lead to": 0.5,
                "limited impact": 0.5,
                "security bulletin": 0.5,
                "security advisory": 0.5,
                "information disclosure": 0.5,
                "denial of service": 0.5
            },
            "low": {
                "low impact": 0.3,
                "minor": 0.3,
                "minimal": 0.3,
                "unlikely": 0.2,
                "theoretical": 0.2,
                "low priority": 0.3,
                "low risk": 0.3
            }
        }
        
        # Combine all keywords for easier searching
        self.all_keywords = {}
        for level, keywords in self.severity_keywords.items():
            for keyword, weight in keywords.items():
                self.all_keywords[keyword] = (level, weight)
                
        # Create regex patterns for each keyword
        self.keyword_patterns = {
            keyword: re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
            for keyword in self.all_keywords.keys()
        }
        
        # CVE scoring patterns
        self.cvss_pattern = re.compile(r'CVSS(?:v\d)?\s+(?:Base\s+)?Score:\s*(\d+\.\d+)', re.IGNORECASE)
        
        # Patterns that might negate severity
        self.negation_patterns = [
            re.compile(r'\b(?:not|no longer|isn\'t|doesn\'t|won\'t|cannot|can\'t|never)\b', re.IGNORECASE),
            re.compile(r'\b(?:mitigated|resolved|fixed|patched|addressed)\b', re.IGNORECASE)
        ]
    
    def _check_negation(self, text: str, start_pos: int, window_size: int = 10) -> bool:
        """
        Check if a keyword might be negated by nearby text.
        
        Args:
            text: The full text
            start_pos: Starting position of the keyword
            window_size: Number of words to check before the keyword
            
        Returns:
            True if negation is detected, False otherwise
        """
        # Extract text window before the keyword
        text_before = text[:start_pos].strip()
        words_before = text_before.split()[-window_size:] if len(text_before.split()) > window_size else text_before.split()
        window_text = ' '.join(words_before)
        
        # Check for negation patterns
        for pattern in self.negation_patterns:
            if pattern.search(window_text):
                return True
                
        return False
    
    def analyze_cvss_score(self, text: str) -> Optional[float]:
        """
        Extract CVSS score from text if present.
        
        Args:
            text: The text to analyze
            
        Returns:
            CVSS score as float if found, None otherwise
        """
        match = self.cvss_pattern.search(text)
        if match:
            try:
                score = float(match.group(1))
                return score
            except ValueError:
                pass
        return None
    
    def analyze_text(self, text: str) -> SeverityAssessment:
        """
        Analyze text to determine overall threat severity.
        
        Args:
            text: The text to analyze
            
        Returns:
            SeverityAssessment with the determined severity
        """
        severity_scores = {
            "critical": 0.0,
            "high": 0.0,
            "medium": 0.0,
            "low": 0.0
        }
        
        evidence = []
        total_weight = 0.0
        
        # Look for CVSS score
        cvss_score = self.analyze_cvss_score(text)
        if cvss_score:
            # Convert CVSS score (0-10) to severity level
            if cvss_score >= 9.0:
                severity_scores["critical"] += 2.0
                evidence.append(f"CVSS Score: {cvss_score} (Critical)")
            elif cvss_score >= 7.0:
                severity_scores["high"] += 2.0
                evidence.append(f"CVSS Score: {cvss_score} (High)")
            elif cvss_score >= 4.0:
                severity_scores["medium"] += 2.0
                evidence.append(f"CVSS Score: {cvss_score} (Medium)")
            else:
                severity_scores["low"] += 2.0
                evidence.append(f"CVSS Score: {cvss_score} (Low)")
                
            total_weight += 2.0
        
        # Check for severity keywords
        for keyword, pattern in self.keyword_patterns.items():
            for match in pattern.finditer(text):
                level, weight = self.all_keywords[keyword]
                
                # Check for negation
                if self._check_negation(text, match.start()):
                    continue
                    
                severity_scores[level] += weight
                total_weight += weight
                evidence.append(f"Keyword: '{keyword}' ({level.capitalize()}, weight: {weight})")
        
        # If no evidence found
        if total_weight == 0:
            return SeverityAssessment(
                severity_score=0.0,
                severity_level="unknown",
                confidence=0.0,
                evidence=["No severity indicators found in text"]
            )
        
        # Calculate weighted severity score (0.0 to 1.0)
        weighted_score = (
            (severity_scores["critical"] * 1.0) + 
            (severity_scores["high"] * 0.75) + 
            (severity_scores["medium"] * 0.5) + 
            (severity_scores["low"] * 0.25)
        ) / total_weight
        
        # Determine severity level based on weighted score
        severity_level = "unknown"
        if weighted_score >= 0.8:
            severity_level = "critical"
        elif weighted_score >= 0.6:
            severity_level = "high"
        elif weighted_score >= 0.4:
            severity_level = "medium"
        elif weighted_score > 0:
            severity_level = "low"
        
        # Calculate confidence based on evidence quantity and diversity
        confidence = min(0.5 + (len(evidence) * 0.1), 1.0)
        
        return SeverityAssessment(
            severity_score=weighted_score,
            severity_level=severity_level,
            confidence=confidence,
            evidence=evidence
        )
    
    def analyze_entity(self, entity: ExtractedEntity, text: str) -> SeverityAssessment:
        """
        Analyze the severity associated with a specific entity.
        
        Args:
            entity: The entity to analyze
            text: The full text for context
            
        Returns:
            SeverityAssessment for the entity
        """
        # Use the entity's context if available, otherwise use the full text
        context = entity.context if entity.context else text
        
        # Get base severity assessment from the context
        assessment = self.analyze_text(context)
        assessment.entity = entity
        
        # Additional entity-specific severity factors
        if entity.entity_type == "cve":
            # CVEs are inherently concerning
            assessment.severity_score = max(assessment.severity_score, 0.5)
            if assessment.severity_level == "unknown":
                assessment.severity_level = "medium"
                assessment.evidence.append("Entity is a CVE identifier")
                
        elif entity.entity_type in ["ipv4", "ipv6", "domain"] and "malicious" in context.lower():
            # Directly labeled as malicious
            assessment.severity_score = max(assessment.severity_score, 0.7)
            if assessment.severity_level in ["unknown", "low"]:
                assessment.severity_level = "high"
                assessment.evidence.append("Entity is described as malicious")
        
        return assessment
