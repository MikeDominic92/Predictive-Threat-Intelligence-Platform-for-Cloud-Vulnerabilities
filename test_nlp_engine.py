#!/usr/bin/env python
"""
Test script for the NLP Engine.

This script demonstrates the capabilities of the NLP Engine
for extracting threat intelligence from unstructured text.
"""

import os
import sys
import json
import argparse
from typing import Dict, Any

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

# Import NLP components
from nlp_engine.nlp_processor import NLPProcessor
from nlp_engine.preprocessors.text_cleaner import TextCleaner
from nlp_engine.extractors.entity_extractor import EntityExtractor

# Sample threat intelligence texts for testing
SAMPLE_TEXTS = {
    "basic": """
    A new malware campaign has been identified targeting financial institutions.
    The malware communicates with command and control servers at 192.168.1.100 and
    evil-domain.com. It exploits CVE-2023-1234, which has a CVSS Score: 8.5.
    The attackers are using phishing emails with malicious attachments (MD5: 
    d41d8cd98f00b204e9800998ecf8427e). This is a critical threat requiring immediate action.
    """,
    
    "apt_report": """
    THREAT INTELLIGENCE REPORT: APT-41
    
    We have observed a sophisticated campaign attributed to APT-41 targeting 
    healthcare organizations. The threat actors are using spear-phishing emails
    with malicious attachments that exploit CVE-2022-0123, a critical vulnerability
    with CVSS Score: 9.8.
    
    Indicators of Compromise:
    - C2 Domains: apt41-control.com, update-service.net
    - IP Addresses: 45.77.123.45, 192.168.22.123 (internal pivoting)
    - File Hashes: 
      - SHA256: 8a9f98c1771e805343d9ec29314e642627d31c0d5c9af44ef0a069af2a7ba826
      - MD5: 5f4dcc3b5aa765d61d8327deb882cf99
    
    The malware uses HTTPS to communicate with its C2 infrastructure and encrypts data
    with AES-256. Upon infection, it collects system information and medical records,
    which are exfiltrated to the C2 servers. This represents a serious threat to
    patient privacy and healthcare operations.
    
    Remediation actions should be taken immediately. This campaign is considered
    high-severity due to the potential impact and sophisticated techniques employed.
    """,
    
    "vulnerability_bulletin": """
    SECURITY BULLETIN: Apache Log4j Vulnerability
    
    A critical remote code execution vulnerability (CVE-2021-44228) has been
    discovered in Apache Log4j, a popular Java logging library. This vulnerability,
    also known as Log4Shell, has a CVSS Base Score of 10.0 (Critical).
    
    The vulnerability allows attackers to execute arbitrary code by sending a
    specially crafted request that includes a malicious JNDI lookup. This affects
    many enterprise applications and services using Log4j versions 2.0 to 2.14.1.
    
    We have observed active exploitation from multiple threat actors, including
    nation-state groups. Scanning activity has been detected from the following IPs:
    - 198.51.100.23
    - 203.0.113.42
    
    Malicious domains involved in exploitation:
    - log4j-exploit.example.com
    - ldap-injection.malicious.org
    
    Organizations should update to Log4j 2.15.0 or later immediately. This is an
    actively exploited zero-day vulnerability requiring urgent attention.
    """
}


def format_entity_output(entity_dict):
    """Format entity dictionary for pretty printing."""
    output = ""
    for entity_type, entities in entity_dict.items():
        output += f"\n  {entity_type.upper()}:\n"
        for entity in entities:
            value = entity.get('value', 'Unknown')
            confidence = entity.get('confidence', 1.0)
            output += f"    - {value} (confidence: {confidence:.2f})\n"
            
            # Print context snippet if available
            context = entity.get('context', '')
            if context and len(context) > 50:
                context = context[:50] + "..."
            if context:
                output += f"      Context: \"{context}\"\n"
    
    return output


def format_relationship_output(relationships):
    """Format relationships for pretty printing."""
    output = ""
    for rel in relationships:
        source = rel.get('source', {}).get('value', 'Unknown')
        target = rel.get('target', {}).get('value', 'Unknown')
        rel_type = rel.get('relationship_type', 'related_to')
        confidence = rel.get('confidence', 0.0)
        
        output += f"\n  {source} {rel_type} {target} (confidence: {confidence:.2f})"
        
        # Add evidence if available
        evidence = rel.get('evidence', '')
        if evidence:
            output += f"\n    Evidence: \"{evidence}\""
    
    return output


def format_severity_output(severity):
    """Format severity assessment for pretty printing."""
    level = severity.get('severity_level', 'unknown')
    score = severity.get('severity_score', 0.0)
    confidence = severity.get('confidence', 0.0)
    
    output = f"\n  Level: {level.upper()}"
    output += f"\n  Score: {score:.2f}/1.00"
    output += f"\n  Confidence: {confidence:.2f}"
    
    # Add evidence
    evidence = severity.get('evidence', [])
    if evidence:
        output += "\n  Evidence:"
        for item in evidence[:5]:  # Show top 5 pieces of evidence
            output += f"\n    - {item}"
        if len(evidence) > 5:
            output += f"\n    - ... and {len(evidence) - 5} more"
    
    return output


def format_indicators_output(indicators):
    """Format risk prediction indicators for pretty printing."""
    output = ""
    for indicator in indicators:
        indicator_type = indicator.get('indicator_type', 'unknown')
        value = indicator.get('value', '')
        tags = indicator.get('tags', [])
        
        output += f"\n  {indicator_type}: {value}"
        if tags:
            output += f" (Tags: {', '.join(tags)})"
    
    return output


def process_sample(processor, text_name, text):
    """Process a sample text and print the results."""
    print(f"\n{'=' * 80}")
    print(f"PROCESSING SAMPLE: {text_name.upper()}")
    print(f"{'=' * 80}\n")
    
    # Process the text
    result = processor.process_text(text, {"source": f"sample_{text_name}"})
    result_dict = result.to_dict()
    
    # Extract indicators for risk prediction
    indicators = result.get_indicators_for_prediction()
    
    # Print analysis results
    print(f"Text length: {len(text)} characters")
    print(f"Entities found: {sum(len(entities) for entities in result.entities.values())} across {len(result.entities)} types")
    
    print("\nEXTRACTED ENTITIES:")
    print(format_entity_output(result_dict['entities']))
    
    print("\nRELATIONSHIPS:")
    if result_dict['relationships']:
        print(format_relationship_output(result_dict['relationships']))
    else:
        print("\n  No relationships identified")
    
    print("\nTEXT SEVERITY ASSESSMENT:")
    print(format_severity_output(result_dict['text_severity']))
    
    print("\nINDICATORS FOR RISK PREDICTION:")
    if indicators:
        print(format_indicators_output(indicators))
    else:
        print("\n  No indicators extracted for risk prediction")
    
    print(f"\n{'=' * 80}\n")
    
    return result


def main():
    """Main function for testing the NLP Engine."""
    parser = argparse.ArgumentParser(description='Test the NLP Engine with sample texts')
    parser.add_argument('--sample', choices=['basic', 'apt_report', 'vulnerability_bulletin', 'all'],
                        default='all', help='Sample text to process')
    parser.add_argument('--output', type=str, help='Output JSON file for results')
    args = parser.parse_args()
    
    # Initialize the NLP processor
    processor = NLPProcessor(
        remove_urls=False,
        remove_html=True,
        normalize_whitespace=True
    )
    
    results = {}
    
    # Process requested samples
    if args.sample == 'all':
        for name, text in SAMPLE_TEXTS.items():
            results[name] = process_sample(processor, name, text)
    else:
        text = SAMPLE_TEXTS[args.sample]
        results[args.sample] = process_sample(processor, args.sample, text)
    
    # Save results to JSON if output file specified
    if args.output:
        output_data = {name: result.to_dict() for name, result in results.items()}
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2)
        print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
