"""
NLP Processor Module.

This module provides the main NLP processing pipeline for threat intelligence,
integrating text preprocessing, entity extraction, relationship analysis,
and severity assessment.
"""

import json
import logging
from typing import List, Dict, Any, Optional, Union, Tuple
from dataclasses import dataclass, asdict

from .preprocessors.text_cleaner import TextCleaner
from .extractors.entity_extractor import EntityExtractor, ExtractedEntity
from .analyzers.relationship_analyzer import RelationshipAnalyzer, EntityRelationship
from .analyzers.severity_analyzer import SeverityAnalyzer, SeverityAssessment

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('nlp_engine.processor')


@dataclass
class NLPAnalysisResult:
    """Container for the complete NLP analysis results."""
    entities: Dict[str, List[ExtractedEntity]]
    relationships: List[EntityRelationship]
    text_severity: SeverityAssessment
    entity_severities: List[SeverityAssessment]
    source_text: str
    preprocessed_text: str
    metadata: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis results to dictionary format."""
        result = {
            "source_text_length": len(self.source_text),
            "preprocessed_text_length": len(self.preprocessed_text),
            "entities": {},
            "relationships": [],
            "text_severity": self.text_severity.to_dict(),
            "entity_severities": [],
            "metadata": self.metadata or {}
        }
        
        # Convert entities
        for entity_type, entities in self.entities.items():
            result["entities"][entity_type] = [entity.to_dict() for entity in entities]
        
        # Convert relationships
        result["relationships"] = [rel.to_dict() for rel in self.relationships]
        
        # Convert entity severities
        result["entity_severities"] = [sev.to_dict() for sev in self.entity_severities]
        
        return result
    
    def get_indicators_for_prediction(self) -> List[Dict[str, Any]]:
        """
        Extract threat indicators in a format suitable for the risk prediction API.
        
        Returns:
            List of indicator dictionaries ready for risk prediction
        """
        indicators = []
        
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
        
        # Process each entity
        for entity_type, entities in self.entities.items():
            indicator_type = type_mapping.get(entity_type, entity_type)
            
            for entity in entities:
                # Find the severity assessment for this entity
                severity = next((s for s in self.entity_severities 
                               if s.entity and s.entity.value == entity.value), None)
                
                # Add tags based on severity if available
                tags = ["extracted", f"type:{entity_type}"]
                if severity and severity.severity_level != "unknown":
                    tags.append(f"severity:{severity.severity_level}")
                
                indicators.append({
                    "indicator_type": indicator_type,
                    "value": entity.value,
                    "source": "nlp_extraction",
                    "tags": tags
                })
        
        return indicators
    
    def get_highlighted_text(self) -> Dict[str, Any]:
        """
        Generate a version of the text with highlighted entities.
        
        Returns:
            Dictionary with original text and highlight positions
        """
        highlights = []
        
        # Collect all entities with positions
        all_entities = []
        for entity_list in self.entities.values():
            all_entities.extend(entity_list)
        
        # Create highlight objects
        for entity in all_entities:
            if entity.position:
                start, end = entity.position
                
                # Find severity for this entity
                severity = next((s for s in self.entity_severities 
                               if s.entity and s.entity.value == entity.value), None)
                
                severity_level = severity.severity_level if severity else "unknown"
                
                highlights.append({
                    "start": start,
                    "end": end,
                    "text": entity.value,
                    "type": entity.entity_type,
                    "severity": severity_level
                })
        
        return {
            "text": self.source_text,
            "highlights": sorted(highlights, key=lambda h: h["start"])
        }


class NLPProcessor:
    """
    Main NLP processing pipeline for threat intelligence.
    
    This class orchestrates the various NLP components to process
    unstructured text and extract structured threat intelligence.
    """
    
    def __init__(self, 
                 remove_urls: bool = False,
                 remove_html: bool = True,
                 normalize_whitespace: bool = True):
        """
        Initialize the NLP processor with components and settings.
        
        Args:
            remove_urls: Whether to remove URLs during cleaning
            remove_html: Whether to remove HTML tags during cleaning
            normalize_whitespace: Whether to normalize whitespace during cleaning
        """
        logger.info("Initializing NLP processor")
        
        # Initialize components
        self.text_cleaner = TextCleaner(
            remove_urls=remove_urls,
            remove_html=remove_html,
            normalize_whitespace=normalize_whitespace,
            lowercase=True,
            remove_punctuation=False,
            keep_special_tokens=True
        )
        
        self.entity_extractor = EntityExtractor()
        self.relationship_analyzer = RelationshipAnalyzer()
        self.severity_analyzer = SeverityAnalyzer()
        
        logger.info("NLP processor initialized")
    
    def process_text(self, text: str, metadata: Dict[str, Any] = None) -> NLPAnalysisResult:
        """
        Process text through the complete NLP pipeline.
        
        Args:
            text: Raw text to process
            metadata: Optional metadata about the text source
            
        Returns:
            Complete NLP analysis results
        """
        if not text or not text.strip():
            logger.warning("Empty text provided for processing")
            return NLPAnalysisResult(
                entities={},
                relationships=[],
                text_severity=SeverityAssessment(),
                entity_severities=[],
                source_text="",
                preprocessed_text="",
                metadata=metadata or {}
            )
        
        logger.info(f"Processing text ({len(text)} characters)")
        
        # Step 1: Preprocess the text for analysis but not for entity extraction
        preprocessed_text = self.text_cleaner.clean(text)
        logger.info(f"Preprocessed text ({len(preprocessed_text)} characters)")
        
        # Step 2: Extract entities from original text (not preprocessed)
        # This ensures we don't miss entities due to preprocessing changes
        entity_dict = self.entity_extractor.extract_all(text)
        all_entities = [entity for entity_list in entity_dict.values() for entity in entity_list]
        logger.info(f"Extracted {len(all_entities)} entities across {len(entity_dict)} types")
        
        # Step 3: Analyze entity relationships
        relationships = self.relationship_analyzer.analyze(preprocessed_text, all_entities)
        logger.info(f"Identified {len(relationships)} relationships between entities")
        
        # Step 4: Analyze severity
        text_severity = self.severity_analyzer.analyze_text(preprocessed_text)
        logger.info(f"Text severity: {text_severity.severity_level} ({text_severity.severity_score:.2f})")
        
        # Step 5: Analyze entity-specific severities
        entity_severities = []
        for entity in all_entities:
            severity = self.severity_analyzer.analyze_entity(entity, preprocessed_text)
            entity_severities.append(severity)
        
        return NLPAnalysisResult(
            entities=entity_dict,
            relationships=relationships,
            text_severity=text_severity,
            entity_severities=entity_severities,
            source_text=text,
            preprocessed_text=preprocessed_text,
            metadata=metadata
        )
    
    def process_document(self, document: Dict[str, Any]) -> NLPAnalysisResult:
        """
        Process a document with text and metadata.
        
        Args:
            document: Dictionary containing 'text' and optional 'metadata'
            
        Returns:
            Complete NLP analysis results
        """
        text = document.get('text', '')
        metadata = document.get('metadata', {})
        return self.process_text(text, metadata)
    
    def batch_process(self, texts: List[str]) -> List[NLPAnalysisResult]:
        """
        Process multiple texts in batch.
        
        Args:
            texts: List of raw texts to process
            
        Returns:
            List of NLP analysis results
        """
        return [self.process_text(text) for text in texts]
    
    @staticmethod
    def save_results_json(result: NLPAnalysisResult, file_path: str) -> None:
        """
        Save analysis results to JSON file.
        
        Args:
            result: Analysis results to save
            file_path: Path to save the JSON file
        """
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2)
        
        logger.info(f"Results saved to {file_path}")


# Simplified interface function for easy usage
def analyze_text(text: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Analyze text for threat intelligence (simplified interface).
    
    Args:
        text: Raw text to analyze
        metadata: Optional metadata about the source
        
    Returns:
        Dictionary with analysis results
    """
    processor = NLPProcessor()
    result = processor.process_text(text, metadata)
    return result.to_dict()


if __name__ == "__main__":
    # Simple demo when run directly
    test_text = """
    A new malware campaign has been identified targeting financial institutions.
    The malware communicates with command and control servers at 192.168.1.100 and
    evil-domain.com. It exploits CVE-2023-1234, which has a CVSS Score: 8.5.
    The attackers are using phishing emails with malicious attachments (MD5: 
    d41d8cd98f00b204e9800998ecf8427e). This is a critical threat requiring immediate action.
    """
    
    processor = NLPProcessor()
    result = processor.process_text(test_text, {"source": "demo"})
    
    print("\n=== NLP Analysis Results ===\n")
    
    # Print entities
    print("Entities found:")
    for entity_type, entities in result.entities.items():
        print(f"  {entity_type}:")
        for entity in entities:
            print(f"    - {entity.value}")
    
    # Print relationships
    print("\nRelationships:")
    for rel in result.relationships:
        print(f"  {rel.source.value} {rel.relationship_type} {rel.target.value}")
    
    # Print severity
    print(f"\nText severity: {result.text_severity.severity_level} " 
          f"(Score: {result.text_severity.severity_score:.2f}, " 
          f"Confidence: {result.text_severity.confidence:.2f})")
    
    # Print most relevant evidence
    print("\nEvidence:")
    for evidence in result.text_severity.evidence[:3]:
        print(f"  - {evidence}")
    
    # Print threat indicators for risk prediction
    print("\nExtracted indicators for risk prediction:")
    for indicator in result.get_indicators_for_prediction():
        print(f"  - {indicator['indicator_type']}: {indicator['value']} (Tags: {indicator['tags']})")
    
    print("\nDemo complete. Use NLPProcessor for more detailed analysis.")
