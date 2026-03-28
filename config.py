"""
Configuration settings - Updated with filtering options
"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / 'output'
URLS_DIR = OUTPUT_DIR / 'urls'
INPUT_FIELDS_DIR = OUTPUT_DIR / 'input_fields'

# Create directories
for dir_path in [OUTPUT_DIR, URLS_DIR, INPUT_FIELDS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Crawler settings
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
REQUEST_TIMEOUT = 10
MAX_RETRIES = 30
DELAY_BETWEEN_REQUESTS = 1
MAX_URLS = 500

# URL filtering settings
FILTER_NON_HTML = True  # Skip non-HTML files
SKIP_EXTENSIONS = [
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.tar', '.gz',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
    '.exe', '.msi', '.dmg', '.app',
    '.css', '.js', '.json', '.xml', '.rss'
]

# AI settings
AI_MODEL = "gemma3:1b"
AI_TIMEOUT = 30

# Pentesting settings
MAX_TEST_ATTEMPTS = 5
CONFIDENCE_THRESHOLD = {
    'high': 0.8,
    'medium': 0.5,
    'low': 0.3
}