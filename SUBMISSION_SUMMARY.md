# Project Experience / Explanation — SISA Hackathon

## 📝 Project Details
- **Candidate Name**: [Your Name]
- **Domain**: Software Development
- **Project Title**: AI Secure Data Intelligence Platform (AI Gateway + Scanner + Log Analyzer + Risk Engine)

---

## 🔍 Problem Solved
In modern enterprises, data flows through multiple sources—logs, chat, SQL, and files. Security teams often struggle to:
1.  **Identify PII/Secrets** across diverse formats (especially log files and unstructured documents).
2.  **Correlate risks** between different events (e.g., a brute-force attempt leading to an API key exposure).
3.  **Provide actionable insights** rather than just raw findings.
4.  **Enforce policies** like masking or blocking automatically.

## 💡 Solution Approach & Design
I designed a **modular, multi-engine architecture** that processes data in a strictly ordered pipeline:
1.  **Ingestion & Parsing Layer**: High-performance extraction of text from PDF, DOC, and Log formats.
2.  **Detection Engine**: A robust regex-based scanner with 15+ patterns for PII, AWS keys, and credentials.
3.  **Advanced Log Analyzer**: Specialized parsing of system logs to identify stack traces, brute-force anomalies, and debug mode leaks.
4.  **Risk Engine**: Uses a weighted scoring model to categorize risks into Critical, High, Medium, and Low levels.
5.  **Policy Engine**: Implements context-aware masking (e.g., `sk-prod-•••`) to ensure data privacy without losing technical context.
6.  **AI Insights Layer**: Integrates Gemini 1.5 Flash for high-level security reporting, with a sophisticated **Rule-Based Fallback** engine ensuring 100% reliability.

## 🛠️ Technologies Used
- **Backend Framework**: FastAPI (Asynchronous Python)
- **AI/LLM**: Google Gemini 1.5 Flash API
- **Parsers**: PyPDF2, python-docx, python-dotenv
- **Frontend**: Vanilla JavaScript (ES6+), HTML5, CSS3 (Custom Glassmorphism Design)
- **Architecture**: Micro-modular (easy to extend with new detection patterns or engines)

## 🚀 Key Features for Evaluation
- **Unified Analysis Dashboard**: Analyze any data type in a single, premium UI.
- **Dynamic Risk Gauge**: Immediate visual feedback of security posture.
- **Log Viewer with Highlighting**: Automatically identifies and highlights sensitive lines in large logs.
- **Intelligent Fallback**: Works perfectly as a local expert system even without an API key.

## 🧬 Challenges Faced
- **Type Hinting & Serialization**: Handling complex nested dictionary responses in FastAPI required careful Pydantic modeling to ensure stable serialization during high-volume analysis.
- **Large Log Parsing**: Processing files line-by-line while maintaining high performance for the UI required optimized string manipulations and state management.
- **Cross-Platform Routing**: Ensuring the frontend could load assets correctly both when served via FastAPI and when opened as a static file.

---

**Originality Statement**: This project was developed entirely during the hackathon period from scratch, specifically tailored to meet SISA's security intelligence requirements.
