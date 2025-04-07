"""
Relationship Analyzer Module.

This module analyzes relationships between extracted entities and determines
the nature of their connections in the context of threat intelligence.
"""

import re
from typing import List, Dict, Any, Set, Tuple, Optional
from dataclasses import dataclass, field

from ..extractors.entity_extractor import ExtractedEntity

@dataclass
class EntityRelationship:
    """Represents a relationship between two entities."""
    source: ExtractedEntity
    target: ExtractedEntity
    relationship_type: str
    confidence: float = 0.0
    evidence: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "relationship_type": self.relationship_type,
            "confidence": self.confidence,
            "evidence": self.evidence
        }


class RelationshipAnalyzer:
    """
    Analyzes relationships between extracted threat entities.
    
    This class identifies connections between different threat entities
    based on their proximity, context, and common patterns in threat reporting.
    """
    
    def __init__(self):
        """Initialize the relationship analyzer."""
        # Common relationship patterns in threat intelligence
        self.relationship_patterns = {
            "communicates_with": [
                r"(?P<src>\S+)\s+communicates with\s+(?P<tgt>\S+)",
                r"(?P<src>\S+)\s+connects to\s+(?P<tgt>\S+)",
                r"(?P<src>\S+)\s+reached out to\s+(?P<tgt>\S+)",
                r"connection(?:s)? (?:from|between)\s+(?P<src>\S+)\s+(?:to|and)\s+(?P<tgt>\S+)"
            ],
            "contains": [
                r"(?P<src>\S+)\s+contains\s+(?P<tgt>\S+)",
                r"(?P<src>\S+)\s+embeds\s+(?P<tgt>\S+)",
                r"(?P<src>\S+)\s+dropped\s+(?P<tgt>\S+)",
                r"(?P<tgt>\S+)\s+(?:was|were) found in\s+(?P<src>\S+)"
            ],
            "hosted_on": [
                r"(?P<src>\S+)\s+(?:is|was) hosted on\s+(?P<tgt>\S+)",
                r"(?P<tgt>\S+)\s+hosts\s+(?P<src>\S+)",
                r"(?P<src>\S+)\s+(?:resides|located) on\s+(?P<tgt>\S+)"
            ],
            "exploits": [
                r"(?P<src>\S+)\s+exploits\s+(?P<tgt>\S+)",
                r"(?P<tgt>\S+)\s+(?:is|was) exploited by\s+(?P<src>\S+)",
                r"exploitation of\s+(?P<tgt>\S+)\s+by\s+(?P<src>\S+)"
            ],
            "attributed_to": [
                r"(?P<src>\S+)\s+(?:is|was) attributed to\s+(?P<tgt>\S+)",
                r"(?P<tgt>\S+)\s+(?:is|was) responsible for\s+(?P<src>\S+)",
                r"(?P<tgt>\S+)(?:'s)? campaign using\s+(?P<src>\S+)"
            ]
        }
        
        # Compile all patterns
        self.compiled_patterns = {}
        for rel_type, patterns in self.relationship_patterns.items():
            self.compiled_patterns[rel_type] = [re.compile(p, re.IGNORECASE) for p in patterns]
    
    def analyze_proximity(self, entities: List[ExtractedEntity], 
                         max_tokens_between: int = 10) -> List[EntityRelationship]:
        """
        Analyze entity relationships based on their proximity in text.
        
        This is a simple heuristic method that assumes entities appearing close
        together in text may be related.
        
        Args:
            entities: List of extracted entities
            max_tokens_between: Maximum number of tokens allowed between entities
                                to consider them related
                                
        Returns:
            List of identified entity relationships
        """
        relationships = []
        
        # Sort entities by position
        sorted_entities = sorted(entities, key=lambda e: e.position[0] if e.position else 0)
        
        # Look for pairs that are close to each other
        for i in range(len(sorted_entities) - 1):
            for j in range(i + 1, len(sorted_entities)):
                source = sorted_entities[i]
                target = sorted_entities[j]
                
                # Skip if either entity has no position info
                if not source.position or not target.position:
                    continue
                
                # Calculate token distance (rough approximation)
                # Get the text between these two entities
                text_between_start = source.position[1]
                text_between_end = target.position[0]
                # If we have the original text, use it to count tokens
                # Otherwise use a rough character-based approximation
                if hasattr(source, 'context') and source.context:
                    # Try to extract the text between from context
                    # This is an approximation since contexts might be different
                    text_between = source.context[source.position[1]-source.position[0]:]
                    token_count = len(text_between.split())
                else:
                    # Fallback: estimate based on character distance
                    char_distance = text_between_end - text_between_start
                    # Rough approximation: assume average token length of 5 chars
                    token_count = char_distance // 5
                
                if token_count <= max_tokens_between:
                    # Determine relationship type based on entity types
                    rel_type = self._infer_relationship_type(source.entity_type, target.entity_type)
                    
                    # Calculate confidence based on proximity
                    confidence = 1.0 - (token_count / max_tokens_between)
                    
                    relationships.append(EntityRelationship(
                        source=source,
                        target=target,
                        relationship_type=rel_type,
                        confidence=confidence,
                        evidence=f"Proximity-based relationship ({token_count} tokens apart)"
                    ))
                    
        return relationships
    
    def analyze_context_patterns(self, text: str, entities: List[ExtractedEntity]) -> List[EntityRelationship]:
        """
        Analyze entity relationships based on language patterns in the text.
        
        This method searches for specific language patterns that indicate
        relationships between entities.
        
        Args:
            text: The full text content
            entities: List of extracted entities
            
        Returns:
            List of identified entity relationships
        """
        relationships = []
        entity_map = {e.value: e for e in entities}
        
        # Check each relationship pattern
        for rel_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    src_value = match.group('src')
                    tgt_value = match.group('tgt')
                    
                    # Find matching entities
                    source = None
                    target = None
                    
                    for entity in entities:
                        if entity.value in src_value:
                            source = entity
                        if entity.value in tgt_value:
                            target = entity
                    
                    if source and target:
                        relationships.append(EntityRelationship(
                            source=source,
                            target=target,
                            relationship_type=rel_type,
                            confidence=0.9,  # High confidence for pattern matches
                            evidence=match.group(0)
                        ))
        
        return relationships
    
    def _infer_relationship_type(self, source_type: str, target_type: str) -> str:
        """
        Infer the most likely relationship type based on entity types.
        
        Args:
            source_type: Type of source entity
            target_type: Type of target entity
            
        Returns:
            Most probable relationship type
        """
        # Define common entity type relationships
        if source_type in ('ipv4', 'ipv6') and target_type in ('ipv4', 'ipv6'):
            return "communicates_with"
        
        if source_type in ('ipv4', 'ipv6') and target_type == 'domain':
            return "resolves_to"
            
        if source_type == 'domain' and target_type in ('ipv4', 'ipv6'):
            return "has_ip"
            
        if source_type in ('md5', 'sha1', 'sha256') and target_type in ('ipv4', 'ipv6', 'domain', 'url'):
            return "communicates_with"
            
        if source_type in ('ipv4', 'ipv6', 'domain', 'url') and target_type in ('md5', 'sha1', 'sha256'):
            return "hosts"
            
        if source_type == 'cve' and target_type in ('ipv4', 'ipv6', 'domain', 'url'):
            return "affects"
            
        # Default relationship
        return "related_to"
    
    def merge_relationships(self, relationships: List[EntityRelationship]) -> List[EntityRelationship]:
        """
        Merge duplicate relationships, keeping the one with highest confidence.
        
        Args:
            relationships: List of identified relationships
            
        Returns:
            List of merged relationships
        """
        merged = {}
        
        for rel in relationships:
            # Create key based on entities and relationship type
            key = (rel.source.value, rel.target.value, rel.relationship_type)
            
            if key not in merged or merged[key].confidence < rel.confidence:
                merged[key] = rel
                
        return list(merged.values())
    
    def analyze(self, text: str, entities: List[ExtractedEntity]) -> List[EntityRelationship]:
        """
        Analyze text and entities to identify relationships.
        
        This is the main method that combines proximity analysis and 
        context pattern analysis.
        
        Args:
            text: The full text content
            entities: List of extracted entities
            
        Returns:
            List of identified entity relationships
        """
        proximity_relationships = self.analyze_proximity(entities)
        context_relationships = self.analyze_context_patterns(text, entities)
        
        # Combine and merge relationships
        all_relationships = proximity_relationships + context_relationships
        return self.merge_relationships(all_relationships)
