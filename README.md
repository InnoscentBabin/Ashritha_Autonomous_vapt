# 🔍 Ashritha - AI-Powered Autonomous Web Pentesting Tool

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Ollama](https://img.shields.io/badge/ollama-0.1.9%2B-orange.svg)](https://ollama.ai)
[![PyFiglet](https://img.shields.io/badge/pyfiglet-0.8.1-red.svg)](https://pypi.org/project/pyfiglet/)

> **Ashritha** is an intelligent, autonomous web application security testing tool that combines advanced web crawling with AI-powered vulnerability detection. It uses local LLMs (via Ollama) to analyze, classify, and exploit vulnerabilities with adaptive payload generation.

## 🌟 Features

### 🚀 Current Capabilities
- **Intelligent Web Crawling**: Automatically discovers all endpoints within a domain
- **AI-Powered Vulnerability Classification**: Uses local LLMs (Gemma3, Llama2, etc.) to analyze endpoints
- **Adaptive Payload Generation**: Generates context-aware payloads based on response analysis
- **SQL Injection Detection**: 
  - Error-based detection
  - Boolean-based blind injection
  - Time-based blind injection
  - Database type fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- **Cross-Site Scripting (XSS)**:
  - Context detection (HTML, attribute, JavaScript)
  - Filter bypass techniques
  - Reflected XSS detection
- **Command Injection**:
  - OS detection (Linux/Windows)
  - Command execution verification
  - Various injection techniques
- **IDOR Detection** (In Development - Gray Box Testing)
- **Authentication Testing** (In Development - Gray Box Testing)

### 🔮 Future Capabilities (Gray Box Testing)
- **IDOR (Insecure Direct Object References)**:
  - Sequential ID enumeration
  - Parameter manipulation
  - Access control bypass detection
- **Authentication Testing**:
  - Default credentials testing
  - Session token analysis
  - JWT vulnerability detection
  - Multi-factor authentication bypass
- **File Inclusion (LFI/RFI)**
- **CSRF Detection**
- **API Security Testing**
- **Business Logic Flaws**

### 🎯 Key Features
- **Zero Dependencies on Cloud APIs**: All processing happens locally via Ollama
- **Adaptive Learning**: Payloads evolve based on server responses
- **Confidence-Based Testing**: Prioritizes high-confidence vulnerabilities
- **Multi-Model Support**: Works with any Ollama-compatible model
- **Modular Architecture**: Easy to extend with new vulnerability modules
- **Beautiful Console Output**: PyFiglet banners and color-coded results

## 📋 Prerequisites

### System Requirements
- **Operating System**: Linux, macOS, Windows (WSL recommended)
- **Python**: 3.8 or higher
- **RAM**: Minimum 4GB (8GB+ recommended for LLM)
- **Storage**: 2GB for models + tool

### Required Software
1. **Ollama**: Local LLM server
   ```bash
   # Install Ollama
   curl -fsSL https://ollama.ai/install.sh | sh
   
   # Pull required models
   ollama pull gemma3:1b    # Lightweight (recommended for quick tests)
   ollama pull llama2        # More powerful (slower but better detection)

   🛠️ Usage
   
   # Full pentest (crawl + test)
   python ashritha.py --mode full --url https://target.com

   # Quick scan (faster, limited pages)
   python ashritha.py --mode full --url https://target.com --quick --max-urls 20

   # Crawl only (save for later)
   python ashritha.py --mode crawl --url https://target.com --max-urls 50
