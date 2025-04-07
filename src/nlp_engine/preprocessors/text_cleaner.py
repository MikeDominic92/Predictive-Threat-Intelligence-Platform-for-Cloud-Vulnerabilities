"""
Text Cleaner Module for NLP preprocessing.

This module provides functions for cleaning and normalizing raw text
from various sources before further processing.
"""

import re
import unicodedata
import string
from typing import List, Dict, Any, Optional

class TextCleaner:
    """
    Handles text cleaning and normalization for threat intelligence NLP.
    
    This class provides methods for removing HTML tags, normalizing whitespace,
    removing unnecessary punctuation, and other text preprocessing tasks.
    """
    
    def __init__(self, 
                 remove_urls: bool = True,
                 remove_html: bool = True,
                 normalize_whitespace: bool = True,
                 lowercase: bool = True,
                 remove_punctuation: bool = False,
                 keep_special_tokens: bool = True):
        """
        Initialize the TextCleaner with preprocessing options.
        
        Args:
            remove_urls: Whether to remove URLs from text
            remove_html: Whether to remove HTML tags
            normalize_whitespace: Whether to normalize all whitespace to single spaces
            lowercase: Whether to convert text to lowercase
            remove_punctuation: Whether to remove punctuation
            keep_special_tokens: Whether to preserve special tokens like IP addresses and domains
        """
        self.remove_urls = remove_urls
        self.remove_html = remove_html
        self.normalize_whitespace = normalize_whitespace
        self.lowercase = lowercase
        self.remove_punctuation = remove_punctuation
        self.keep_special_tokens = keep_special_tokens
        
        # Regular expressions for cleaning
        self.url_pattern = re.compile(r'https?://\S+|www\.\S+')
        self.html_pattern = re.compile(r'<.*?>')
        self.whitespace_pattern = re.compile(r'\s+')
        
        # Patterns for special tokens we want to preserve
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
        self.hash_pattern = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
        
        # Store special tokens for reinsertion
        self.special_tokens = {}
    
    def _extract_preserve_special_tokens(self, text: str) -> str:
        """Extract special tokens that should be preserved during cleaning."""
        if not self.keep_special_tokens:
            return text
            
        # Reset special tokens
        self.special_tokens = {}
        
        # We need to make exact non-overlapping replacements to avoid issues
        # First find all matches with their positions
        token_matches = []
        
        # Extract IPs with positions
        for match in self.ip_pattern.finditer(text):
            token_matches.append({
                'start': match.start(),
                'end': match.end(),
                'value': match.group(0),
                'type': 'IP'
            })
        
        # Extract domains with positions
        for match in self.domain_pattern.finditer(text):
            token_matches.append({
                'start': match.start(),
                'end': match.end(),
                'value': match.group(0),
                'type': 'DOMAIN'
            })
        
        # Extract hashes with positions
        for match in self.hash_pattern.finditer(text):
            token_matches.append({
                'start': match.start(),
                'end': match.end(),
                'value': match.group(0),
                'type': 'HASH'
            })
        
        # Sort by position to replace from end to beginning (to maintain indices)
        token_matches.sort(key=lambda x: x['start'], reverse=True)
        
        # Replace tokens with placeholders
        for i, match in enumerate(token_matches):
            placeholder = f"__{match['type']}_{i}__"
            text = text[:match['start']] + placeholder + text[match['end']:]
            self.special_tokens[placeholder] = match['value']
        
        return text
    
    def _restore_special_tokens(self, text: str) -> str:
        """Restore special tokens that were preserved during cleaning."""
        if not self.keep_special_tokens:
            return text
            
        for placeholder, original in self.special_tokens.items():
            text = text.replace(placeholder, original)
            
        return text
    
    def clean(self, text: str) -> str:
        """
        Clean and normalize text according to initialized settings.
        
        Args:
            text: Raw text to be cleaned
            
        Returns:
            Cleaned and normalized text
        """
        if not text:
            return ""
        
        # Handle special tokens
        if self.keep_special_tokens:
            text = self._extract_preserve_special_tokens(text)
        
        # Remove URLs if enabled
        if self.remove_urls:
            text = self.url_pattern.sub(' ', text)
        
        # Remove HTML if enabled
        if self.remove_html:
            text = self.html_pattern.sub(' ', text)
        
        # Convert to lowercase if enabled
        if self.lowercase:
            text = text.lower()
        
        # Remove punctuation if enabled
        if self.remove_punctuation:
            translator = str.maketrans('', '', string.punctuation)
            text = text.translate(translator)
        
        # Normalize whitespace if enabled
        if self.normalize_whitespace:
            text = self.whitespace_pattern.sub(' ', text)
            text = text.strip()
        
        # Restore special tokens
        if self.keep_special_tokens:
            text = self._restore_special_tokens(text)
        
        return text
    
    def batch_clean(self, texts: List[str]) -> List[str]:
        """
        Clean a batch of texts.
        
        Args:
            texts: List of raw texts to clean
            
        Returns:
            List of cleaned texts
        """
        return [self.clean(text) for text in texts]


# Utility functions for additional preprocessing

def remove_stopwords(text: str, stopwords: List[str]) -> str:
    """
    Remove stopwords from text.
    
    Args:
        text: Input text
        stopwords: List of stopwords to remove
        
    Returns:
        Text with stopwords removed
    """
    words = text.split()
    filtered_words = [word for word in words if word.lower() not in stopwords]
    return ' '.join(filtered_words)


def normalize_unicode(text: str) -> str:
    """
    Normalize Unicode characters to their closest ASCII representation.
    
    Args:
        text: Text with potential Unicode characters
        
    Returns:
        Normalized text
    """
    return unicodedata.normalize('NFKD', text).encode('ascii', 'ignore').decode('ascii')
