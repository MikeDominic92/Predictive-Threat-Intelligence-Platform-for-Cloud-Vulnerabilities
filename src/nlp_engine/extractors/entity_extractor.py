"""
Entity Extractor Module.

This module provides functionality for extracting threat-related entities 
from text, including IPs, domains, URLs, file hashes, and CVE identifiers.
"""

import re
import ipaddress
from typing import List, Dict, Any, Set, Tuple, Optional
from dataclasses import dataclass

@dataclass
class ExtractedEntity:
    """Container for extracted entities with metadata."""
    value: str
    entity_type: str
    confidence: float = 1.0
    context: Optional[str] = None
    position: Optional[Tuple[int, int]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "value": self.value,
            "type": self.entity_type,
            "confidence": self.confidence,
            "context": self.context,
            "position": self.position
        }


class EntityExtractor:
    """
    Extracts threat intelligence entities from text.
    
    This class provides methods to identify and extract various types of
    threat indicators including IP addresses, domains, URLs, file hashes,
    and CVE identifiers.
    """
    
    def __init__(self):
        """Initialize the entity extractor with regex patterns."""
        # Regex patterns for different entity types
        self.patterns = {
            "ipv4": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "ipv6": re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
            "domain": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
            "url": re.compile(r'\bhttps?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w%!$&\'()*+,;=:~]+)*(?:\?[-\w%!$&\'()*+,;=:~/.]+)?(?:#[-\w%!$&\'()*+,;=:~/.]+)?\b'),
            "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
            "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
            "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
            "cve": re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        }
        
        # Common false positives to filter out
        self.false_positives = {
            "ipv4": set(['0.0.0.0', '127.0.0.1', '255.255.255.255']),
            "domain": set(['example.com', 'domain.com']),
            "md5": set(),
            "sha1": set(),
            "sha256": set()
        }
        
        # Context window size (chars before/after entity)
        self.context_window = 50
    
    def _validate_ipv4(self, ip: str) -> bool:
        """Validate if string is a legitimate IPv4 address."""
        try:
            # Check if it's a valid IP and not in reserved ranges
            ip_obj = ipaddress.IPv4Address(ip)
            return (not ip_obj.is_multicast and 
                    not ip_obj.is_private and 
                    not ip_obj.is_reserved and 
                    not ip_obj.is_loopback and 
                    ip not in self.false_positives["ipv4"])
        except ValueError:
            return False
    
    def _extract_with_context(self, text: str, pattern, entity_type: str) -> List[ExtractedEntity]:
        """Extract entities with surrounding context."""
        results = []
        for match in pattern.finditer(text):
            value = match.group(0)
            
            # Skip false positives
            if entity_type in self.false_positives and value in self.false_positives[entity_type]:
                continue
                
            # Additional validation for specific types
            if entity_type == "ipv4" and not self._validate_ipv4(value):
                continue
            
            # Get context
            start, end = match.span()
            context_start = max(0, start - self.context_window)
            context_end = min(len(text), end + self.context_window)
            context = text[context_start:context_end]
            
            results.append(ExtractedEntity(
                value=value,
                entity_type=entity_type,
                context=context,
                position=(start, end)
            ))
            
        return results
    
    def extract_all(self, text: str) -> Dict[str, List[ExtractedEntity]]:
        """
        Extract all entity types from text.
        
        Args:
            text: The input text to extract entities from
            
        Returns:
            Dictionary mapping entity types to lists of extracted entities
        """
        result = {}
        
        for entity_type, pattern in self.patterns.items():
            entities = self._extract_with_context(text, pattern, entity_type)
            if entities:
                result[entity_type] = entities
                
        return result
    
    def extract_by_type(self, text: str, entity_type: str) -> List[ExtractedEntity]:
        """
        Extract specific entity type from text.
        
        Args:
            text: The input text to extract entities from
            entity_type: The type of entity to extract
            
        Returns:
            List of extracted entities of the specified type
        """
        if entity_type not in self.patterns:
            raise ValueError(f"Unknown entity type: {entity_type}")
            
        return self._extract_with_context(text, self.patterns[entity_type], entity_type)
    
    def get_unique_values(self, entities: List[ExtractedEntity]) -> Set[str]:
        """
        Get unique values from a list of extracted entities.
        
        Args:
            entities: List of extracted entities
            
        Returns:
            Set of unique entity values
        """
        return {entity.value for entity in entities}
    
    def format_for_prediction(self, entities: Dict[str, List[ExtractedEntity]]) -> List[Dict[str, Any]]:
        """
        Format extracted entities for risk prediction.
        
        Converts extracted entities to the format expected by the risk prediction API.
        
        Args:
            entities: Dictionary of entities by type
            
        Returns:
            List of dictionaries with formatted indicators
        """
        formatted = []
        
        # Map entity types to indicator types
        type_mapping = {
            "ipv4": "ip",
            "ipv6": "ip",
            "domain": "domain",
            "url": "url",
            "md5": "hash",
            "sha1": "hash",
            "sha256": "hash",
            "cve": "cve",
            "email": "email"
        }
        
        for entity_type, entity_list in entities.items():
            indicator_type = type_mapping.get(entity_type, entity_type)
            
            for entity in entity_list:
                formatted.append({
                    "indicator_type": indicator_type,
                    "value": entity.value,
                    "source": "nlp_extraction",
                    "tags": ["extracted", f"type:{entity_type}"]
                })
                
        return formatted
