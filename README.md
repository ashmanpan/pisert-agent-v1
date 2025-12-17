# PSIRT Security Analysis Agent

AI-powered security analysis agent for Cisco PSIRT advisories using LangGraph, Claude, and Qdrant.

## Features

- **PSIRT Data Ingestion**: Fetch security advisories from Cisco OpenVuln API and web scraping
- **AI-Powered Analysis**: Deep vulnerability analysis using Claude LLM
- **Risk Assessment**: Automated risk scoring and prioritization
- **Structured Documents**: Generate detailed security analysis documents
- **Vector Storage**: Store documents in Qdrant for semantic search
- **RAG-based Q&A**: Ask questions about security advisories
- **Device Inventory Matching**: Match vulnerabilities against your device inventory
- **Web Interface**: Modern dashboard for visualization and interaction

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   PSIRT Security Analysis Agent                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Data Ingestion → LangGraph Analysis → Qdrant Storage → RAG Q&A │
│       ↓                  ↓                 ↓              ↓     │
│  Cisco API          Claude LLM        Embeddings      Retriever │
│  Web Scraper        Risk Assessment   Vector Store    Q&A Chain │
│  Excel Parser       Doc Generation    Metadata        Citations │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Using Docker (Recommended)

1. Clone the repository and navigate to the project directory:
```bash
cd psirt-agent
```

2. Create a `.env` file with your API keys:
```bash
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

3. Start the services:
```bash
docker-compose up -d
```

4. Open the web interface at http://localhost:8000

### Manual Installation

1. Install Python 3.11+ and create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Start Qdrant (using Docker):
```bash
docker run -p 6333:6333 -p 6334:6334 qdrant/qdrant
```

4. Set environment variables:
```bash
export ANTHROPIC_API_KEY=your_key_here
```

5. Run the application:
```bash
python -m uvicorn src.main:app --host 0.0.0.0 --port 8000
```

## Usage

### Web Interface

1. **Upload Inventory**: Go to the Inventory tab and upload your Excel file with device information
2. **Run Analysis**: Navigate to the Analyze tab and click "Start Analysis"
3. **Query**: Use the Query tab to ask questions about security advisories
4. **Browse**: View all advisories in the Advisories tab

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check |
| `/api/query` | POST | Query the knowledge base |
| `/api/upload` | POST | Upload device inventory |
| `/api/analyze` | POST | Start PSIRT analysis |
| `/api/advisories` | GET | List all advisories |
| `/api/advisories/{id}` | GET | Get advisory details |
| `/api/statistics` | GET | Get statistics |

### Example Query

```bash
curl -X POST http://localhost:8000/api/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "What critical vulnerabilities affect IOS XR 7.x?",
    "limit": 5
  }'
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude | Yes |
| `CISCO_CLIENT_ID` | Cisco OpenVuln API client ID | No |
| `CISCO_CLIENT_SECRET` | Cisco OpenVuln API client secret | No |
| `QDRANT_HOST` | Qdrant host | No (default: localhost) |
| `QDRANT_PORT` | Qdrant port | No (default: 6333) |
| `QDRANT_COLLECTION` | Collection name | No (default: psirt_advisories) |

### Cisco API Access

To use the Cisco OpenVuln API:
1. Register at https://apiconsole.cisco.com/
2. Create an application and get client credentials
3. Add credentials to your `.env` file

Without API credentials, the agent will use web scraping only.

## Project Structure

```
psirt-agent/
├── src/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration
│   ├── ingestion/           # Data ingestion layer
│   │   ├── excel_parser.py  # Excel file parser
│   │   ├── cisco_api.py     # Cisco API client
│   │   └── web_scraper.py   # Web scraper
│   ├── agents/              # LangGraph agents
│   │   ├── graph.py         # Main workflow
│   │   ├── state.py         # State definitions
│   │   └── nodes/           # Analysis nodes
│   ├── storage/             # Storage layer
│   │   ├── qdrant_store.py  # Qdrant integration
│   │   └── embeddings.py    # Embedding service
│   ├── rag/                 # RAG components
│   │   ├── retriever.py     # Document retriever
│   │   └── qa_chain.py      # Q&A chain
│   └── api/                 # API routes
├── static/                  # Web interface
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## LangGraph Workflow

```
fetch → analyze → assess_risk → generate_doc → store
  ↓         ↓          ↓             ↓           ↓
Get PSIRT  Claude     Risk        Structured   Qdrant
Data       Analysis   Scoring     Documents    Storage
```

## Analysis Output

Each vulnerability is analyzed with:

- **When Is This A Problem**: Conditions when the vulnerability is exploitable
- **Clear Conditions**: Specific requirements for exploitation
- **Risk Assessment**: Severity, CVSS score, exploitability, impact
- **Possibility**: Likelihood, attack vector, complexity
- **Mitigation**: Recommended actions, workarounds, upgrade path
- **Affected Inventory**: Devices in your environment that are affected

## License

MIT License
