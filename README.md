# 🛡️ Nginx AI Security Suite

[![Python][Python-badge]][Python-url]
[![FastAPI][FastAPI-badge]][FastAPI-url]
[![Streamlit][Streamlit-badge]][Streamlit-url]
[![Docker][Docker-badge]][Docker-url]
[![LangChain][LangChain-badge]][LangChain-url]

An AI-powered suite of tools designed to enhance web server security by analyzing Nginx logs and auditing website security headers. This project leverages a hybrid system combining fast regex-based pattern matching with a Retrieval-Augmented Generation (RAG) pipeline using Google's Gemini models to provide intelligent, context-aware security advice.

![Home Page Screenshot](https://raw.githubusercontent.com/andycungkrinx91/Nginx-AI-Security-Suite/master/images/homepage.png)
![Log Analyzer Page Screenshot](https://raw.githubusercontent.com/andycungkrinx91/Nginx-AI-Security-Suite/master/images/log-analyzer.png)
![Website Header Analyzer Page Screenshot](https://raw.githubusercontent.com/andycungkrinx91/Nginx-AI-Security-Suite/master/images/header-analyzer.png)
![Log Analyzer Report Screenshot](https://raw.githubusercontent.com/andycungkrinx91/Nginx-AI-Security-Suite/master/images/report-log-analyzer.png)
![Website Header Analyzer Report Screenshot](https://raw.githubusercontent.com/andycungkrinx91/Nginx-AI-Security-Suite/master/images/report-header-scanner.png)

## 🧐 About The Project

In today's digital landscape, web server security is paramount. Misconfigurations and unmonitored logs can leave servers vulnerable to a wide array of attacks. This project provides a user-friendly interface to powerful AI models, allowing developers and system administrators to proactively identify and mitigate security risks in their Nginx deployments.

The application is composed of two main tools:

* **📄 Log Analyzer:** A powerful tool that ingests Nginx `access.log` files. It first uses a comprehensive set of OWASP-based regular expressions to rapidly identify suspicious patterns, then leverages an AI model to provide a detailed, downloadable PDF report explaining the findings and recommending remediation steps.
* **🌐 Website Header Analyzer:** A passive scanner that audits the HTTP security headers of any live website. It provides a letter grade for the site's security posture and generates a ready-to-use Nginx configuration block to implement missing headers, complete with an AI-generated explanation.

The entire suite is containerized with Docker, ensuring a smooth and consistent setup process across different environments.

---

## ✨ Features

* 🚀 **Hybrid Threat Detection:** Combines high-speed OWASP Top 50 Global Regex scanning for initial threat identification with Google's Gemini models for deep, contextual analysis of the findings.
* 📚 **RAG-Enhanced Intelligence** The system doesn't just find threats, it understands them. By combining the regex findings with a curated knowledge base, the AI provides detailed explanations and context-aware remediation advice, going far beyond simple pattern matching.
* 🖥️ **Interactive Frontend:** A beautiful and responsive multi-page application built with Streamlit.
* ⚙️ **Asynchronous Backend:** A high-performance backend built with FastAPI, capable of handling long-running analysis tasks without blocking the user interface.
* 🔄 **Real-time Updates:** The Log Analyzer uses Server-Sent Events (SSE) to provide real-time status updates to the user while analysis is in progress.
* 📄 **Downloadable PDF Reports:** Generate professional, styled PDF reports from the AI's analysis for easy sharing and record-keeping for both tools.
* 📦 **Containerized & Portable:** Fully containerized with Docker and Docker Compose for easy, one-command setup.

---

## 🛠️ Tech Stack

This project is built with a modern, robust tech stack.

**Backend:**
* ![Python][Python-badge] (Base Programming Language)
* ![FastAPI][FastAPI-badge] (For backend API)
* ![LangChain][LangChain-badge] (for orchestrating the AI pipeline)
* **OWASP** (for regex patterns)
* **Google Generative AI SDK** (for interfacing with Gemini)
* **ReportLab** (for PDF generation)

**Frontend:**
* ![Streamlit][Streamlit-badge] (For Frontend)

**Deployment:**
* ![Docker][Docker-badge] (For Continerized)

---

## 🚀 Getting Started

Follow these instructions to get a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

You must have **Docker** and **Docker Compose** installed on your system.
* [Install Docker](https://docs.docker.com/get-docker/)
* [Install Docker Compose](https://docs.docker.com/compose/install/)

### Installation

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/andycungkrinx91/Nginx-AI-Security-Suite.git
    cd Nginx-AI-Security-Suite
    ```

2.  **Configure Environment Variables:**
    Create a `.env` file in the root directory by copying the example file.
    ```sh
    cp .env-example .env
    ```
    Now, open the `.env` file and add your secret keys:
    ```env
    # Generate a secure, random key for frontend-backend communication
    BACKEND_API_KEY="YOUR_SUPER_SECRET_API_KEY"

    # Your Google AI API Key for Gemini
    GOOGLE_API_KEY="AIzaSy..."

    # (Optional) Specify Gemini model names
    GEMINI_MODEL_NAME="gemini-1.5-flash-latest"
    EMBEDDING_MODEL_NAME="models/text-embedding-004"
    ```

3.  **Build and Run with Docker Compose:**
    This single command will build the Docker images for both the frontend and backend, and start the application.
    ```sh
    docker-compose up --build or docker compose up --build (depends on your docker version)
    ```

4.  **Access the Application:**
    * The Streamlit frontend will be available at: `http://localhost:5000`
    * The FastAPI backend documentation will be available at: `http://localhost:8000/docs`

---

## 📂 Project Structure

The repository is organized into a `backend` and a `frontend` directory, with supporting Docker and configuration files at the root.
```bash
.
├── backend/
│   ├── app/
│   │   ├── analysis.py       # Regex + AI log analysis logic
│   │   ├── scanner.py        # Website header scanning logic
│   │   └── security.py       # API key authentication
│   ├── Dockerfile
│   ├── main.py             # FastAPI entrypoint & endpoints
│   ├── owasp_regex_patterns.txt # Regex patterns for log scanning
│   └── requirements.txt
│
├── frontend/
│   ├── pages/
│   │   ├── Log_Analyzer.py
│   │   └── Website_Header_Analyzer.py
│   ├── Dockerfile
│   ├── Home.py             # Main Streamlit landing page
│   └── requirements.txt
│
├── .env
├── .env-example
├── .gitignore
├── docker-compose.yaml
└── README.md
```

---

## 👤 Contact

Andy Setiyawan - [andy.silva270114@gmail.com](mailto:andy.silva270114@gmail.com)

Project Link: [https://github.com/andycungkrinx91/Nginx-AI-Security-Suite/](https://github.com/andycungkrinx91/Nginx-AI-Security-Suite/)

[Python-badge]: https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white
[Python-url]: https://www.python.org/
[FastAPI-badge]: https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white
[FastAPI-url]: https://fastapi.tiangolo.com/
[Streamlit-badge]: https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white
[Streamlit-url]: https://streamlit.io/
[Docker-badge]: https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white
[Docker-url]: https://www.docker.com/
[LangChain-badge]: https://img.shields.io/badge/LangChain-1E90FF?style=for-the-badge
[LangChain-url]: https://www.langchain.com/