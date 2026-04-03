---
title: Nexus Intelligence Platform
emoji: 🛡️
colorFrom: purple
colorTo: indigo
sdk: docker
pinned: false
---

# 🛡️ Nexus Intelligence Platform

> **Full-spectrum security auditing powered by Gemini AI.**

Nexus Intelligence Platform is a next-generation security analysis tool designed to streamline vulnerability detection for developers and security teams. Built for modern DevOps workflows, it seamlessly combines Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST) into a single, unified dashboard.

## ✨ Key Features

- **🧠 Gemini-Powered Analysis**: Leverages Google's advanced Gemini AI to deeply understand code context, minimizing false positives and providing actionable remediation steps.
- **🔍 GitHub SAST (Static Analysis)**: Instantly analyze source code from any public GitHub repository. Detects hardcoded secrets, injection flaws, insecure dependencies, and architectural vulnerabilities before they hit production.
- **🌐 Cloud DAST (Dynamic Analysis)**: Probe live cloud applications and APIs for dynamic vulnerabilities. Evaluates runtime behavior, misconfigurations, and authentication weaknesses.
- **📊 Unified Dashboard**: View all your security posture metrics, detailed vulnerability reports, and remediation advice in a clean, intuitive, and highly responsive interface.
- **⚡ Real-time Feedback**: Get rapid security insights to fix issues as you code, accelerating the secure software development lifecycle (SSDLC).
- **🛡️ Rate-Limit Resilient**: Built with robust retry-and-fallback mechanisms to ensure continuous analysis even under heavy API load.

## 🛠️ Technology Stack

- **Frontend**: Next.js 16, React 19, Tailwind CSS v4, Lucide Icons
- **Backend**: Next.js API Routes (Serverless)
- **AI Engine**: Google Generative AI (`@google/generative-ai`)
- **Deployment**: Docker-ready, Hugging Face Spaces compatible

## 🚀 Getting Started

### Prerequisites
- Node.js 20+
- A Google Gemini API Key

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/github-vuln-scanner.git
   cd github-vuln-scanner
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure Environment Variables**
   Create a `.env.local` file in the root directory and add your Gemini API key:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

4. **Run the Development Server**
   ```bash
   npm run dev
   ```
   Open [http://localhost:3000](http://localhost:3000) to view the application.

## 🎯 How It Works

1. **Input**: Provide the URL of a public GitHub repository or a live cloud application endpoint.
2. **Scan**: The application securely fetches the target's codebase or probes its live endpoints.
3. **AI Analysis**: The data is sent to the Gemini AI model, which uses specialized prompts to act as a seasoned security auditor identifying potential zero-days, logic flaws, and standard OWASP vulnerabilities.
4. **Report Generation**: A comprehensive, easy-to-read report is generated, complete with severity levels, precise locations of the vulnerabilities, and step-by-step remediation guidance.

## 🏆 Hackathon Judges' Note

This project demonstrates the power of integrating cutting-edge LLMs directly into the DevSecOps pipeline. By automating complex security analysis that traditionally requires specialized human auditors, **Nexus Intelligence Platform** democratizes application security, making it accessible to developers of all skill levels.


