# SkillBridge — AI Layer Backend

> **Autonomous AI Agent for End-to-End Freelance Hiring**  
> From client conversation → requirement extraction → freelancer matching → negotiation → signed contract — fully automated.

---

## 🧠 What Is This?

SkillBridge is an AI-native freelance hiring platform. Unlike traditional platforms where clients manually search and filter profiles, SkillBridge uses an **autonomous multi-agent orchestrator** that handles the entire project lifecycle without human intervention.

This repository contains the **complete AI backend** — the brain of the SkillBridge platform.

**Built by:** Ahmed Raza (AI Engineer)  
**Stack:** Python · FastAPI · LangChain · Groq · Llama 3.3-70B · MongoDB · Redis · TypeScript  
**Model:** `llama-3.3-70b-versatile` hosted on Groq Cloud (sub-800ms responses)

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🤖 **Autonomous Orchestrator** | 5-stage pipeline: Understand → Analyze → Match → Negotiate → Contract |
| 🧩 **Persona Detection** | Real-time Beginner / Intermediate / Advanced user detection — AI adapts language instantly |
| 🔍 **Four Pillars Hard Gate** | Mathematically impossible to trigger matching without Scope + Budget + Stack + Timeline |
| 🎯 **3-Step Fallback Matching** | Exact → Case-insensitive → Category fallback — results always returned |
| 🤝 **Autonomous Negotiation** | AI writes outreach, analyzes replies, applies 20% budget rule for auto-closing deals |
| 🛡️ **4-Layer Moderation** | Blocks vulgarity, PII, jailbreaks, and prompt injections before AI processes any message |
| 🧠 **Two-Tier Memory** | Redis (2hr session) + MongoDB (30-day personalization) |
| ⚡ **Grounded Extraction** | 185 DB skills passed to LLM — prevents hallucinated tech stacks |

---

## 🏗️ Architecture

```
User Message
     │
     ▼
assistant_controller.py   ← Entry point, security check
     │
     ▼
moderation_service.py     ← 4-layer security scan
     │
     ▼
ai_orchestrator.py        ← Brain: stage routing + memory loading
     │
     ├──► conversation_service.py    ← Persona detection + reply generation
     │
     ├──► extraction_service.py      ← Silent Four Pillars mining
     │
     ├──► matching_service.py        ← 3-step DB query + LLM ranking
     │
     ├──► negotiation_service.py     ← Autonomous deal closing
     │
     └──► contract_service.py        ← Legal agreement generation
```

---

## 🔄 The 5-Stage AI Pipeline

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  UNDERSTAND │ →  │   ANALYZE   │ →  │    MATCH    │ →  │  NEGOTIATE  │ →  │  CONTRACT   │
│             │    │             │    │             │    │             │    │             │
│ Chat with   │    │ Extract 4   │    │ DB query +  │    │ AI talks to │    │ Legal doc   │
│ client,     │    │ Pillars,    │    │ LLM ranking,│    │ freelancer, │    │ auto-       │
│ detect      │    │ Hard Gate   │    │ Top 5       │    │ 20% budget  │    │ generated   │
│ persona     │    │ validation  │    │ returned    │    │ rule        │    │ & signed    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

---

## 📁 Project Structure

```
backend/ai/
│
├── orchestrator/
│   └── ai_orchestrator.py          # Main brain — stage routing, memory, pipeline control
│
├── conversation/
│   ├── conversation_service.py     # Persona detection + dialogue generation
│   └── conversation_prompt.py      # Dynamic system prompt builder
│
├── extraction/
│   ├── extraction_service.py       # Four Pillars data miner + completeness checker
│   └── extraction_prompt.py        # Extraction + completeness check prompts
│
├── matching/
│   ├── matching_service.py         # 3-step fallback DB query + category mapping
│   └── ranking_engine.py           # LLM-based freelancer scoring (40/20/20/20)
│
├── moderation/
│   ├── moderation_service.py       # 4-layer security scanner
│   └── moderation_prompt.py        # Moderation prompt builder
│
├── negotiation/
│   ├── negotiation_service.py      # Autonomous negotiation + 20% budget rule
│   └── scoring_service.py          # Real-time freelancer quality evaluator
│
├── contract/
│   └── contract_service.py         # Legal contract auto-generator
│
├── memory/
│   ├── session_service.py          # Redis session + MongoDB long-term memory
│   └── persistent_memory_service.py
│
└── shared/
    ├── constants.py                 # AgentStage, ExpertiseLevel enums
    ├── agent_types.py               # Pydantic models: AgentInput, AgentOutput
    └── llm_service.py               # Groq API abstraction + retry logic
```

---

## 🧩 Module Breakdown

### 🧠 Orchestrator (`ai_orchestrator.py`)
The central router of the entire AI system. Every message passes through here.

- Loads 30-day MongoDB memory at conversation start
- Routes to correct handler based on current stage
- Enforces minimum conversation rounds (BEGINNER=3, INTERMEDIATE=2, ADVANCED=1)
- Runs dual LLM + code validation before triggering match
- Detects hire intent via regex: `hire|want.*hire|go.*with|choose|select|pick`
- Updates long-term memory after every response

### 💬 Conversation Service (`conversation_service.py`)
Handles the AI's voice and personality.

- Detects 6 persona attributes per message: `expertiseLevel`, `userType`, `urgency`, `budgetSensitivity`, `communicationStyle`, `primaryGoal`
- Re-evaluates persona on every message longer than 15 characters
- Auto-generates 3-4 word chat title on first message
- Prunes history to last 20 messages to prevent token overflow
- Falls back to INTERMEDIATE + CONFUSED persona if LLM detection fails

### 🔍 Extraction Service (`extraction_service.py`)
Silently mines conversation for structured project data.

- Fetches all 185 approved skills from MongoDB — grounds LLM to real skills only
- Smart merge: never overwrites existing data with null values
- Makes 2 LLM calls: extract data + check completeness
- Returns `isComplete` boolean + `confidence` score (0-100%)
- Regex-based JSON cleaner handles LLM formatting quirks
- Pydantic `ProjectRequirements` model validates output structure

### 🎯 Matching Service (`matching_service.py`)
Finds and ranks the best freelancers from the database.

**3-Step Fallback Query:**
1. **Exact match** — `skill.name IN [required_skills]`
2. **Case-insensitive regex** — finds "React", "react", "REACT"  
3. **Category fallback** — maps skill → category via `CATEGORY_MAP`, pulls all freelancers in that category

**Skill Decomposition:**
- "MERN" → `["mongodb", "express", "react", "node"]`
- "MEAN" → `["mongodb", "express", "angular", "node"]`

**LLM Ranking Formula:**

| Criteria | Weight |
|----------|--------|
| Skills Match | 40% |
| Budget Fit | 20% |
| Rating | 20% |
| Experience | 20% |

Budget math: `hourlyRate × 160 hours` — exceeds budgetMax = penalized in ranking

### 🛡️ Moderation Service (`moderation_service.py`)
4-layer security before any message is processed.

| Layer | What it blocks |
|-------|---------------|
| Layer 1 | Vulgarity / profanity — de-escalates, redirects |
| Layer 2 | PII — phone numbers, emails (off-platform hiring prevention) |
| Layer 3 | Jailbreaks / prompt injections — stays in persona |
| Layer 4 | Four Pillars Hard Gate — blocks premature matching |

Returns: `violation`, `severity`, `confidence`, `intent`, `suggested_action`, `sanitized_message`, `risk_score_increment`

### 🤝 Negotiation Service (`negotiation_service.py`)
Autonomous deal-closing agent.

- Writes personalized outreach to freelancer mentioning project + skills + budget
- Classifies freelancer replies: `ACCEPTED` / `COUNTERED` / `DECLINED` / `QUESTIONS`
- **20% Budget Rule:** If counter-offer ≤ client's budgetMax × 1.2 → auto-accept at budgetMax
- Uses persuasion tactics for borderline cases: future value, 5-star review potential
- Real-time quality scoring via `scoring_service.py` (score 0-100 + communication/priceFit/skillMatch)

### 🧠 Memory System (`session_service.py`)
Two-tier memory for continuity and personalization.

| Layer | Technology | TTL | Purpose |
|-------|-----------|-----|---------|
| Short-term | Redis | 2 hours | Active conversation history, UI state, session data |
| Long-term | MongoDB | 30 days | Budget preferences, past projects, hired freelancers |

Key: `ai_session:{uuid}` in Redis  
Long-term recall example: *"Welcome back! Last time you worked with a Python developer for $1500 — shall we continue?"*

---

## ⚡ Tech Stack

```
Language:     Python 3.11+
Framework:    FastAPI (async)
LLM:          Llama 3.3-70B via Groq Cloud (LPU architecture, <800ms)
Fallback LLM: Llama 3.1-8B
Orchestration: LangChain
Database:     MongoDB (Motor async driver)
Cache:        Redis
Validation:   Pydantic v2
API:          REST + WebSocket
```

---

## 🚀 Getting Started

### Prerequisites
```bash
Python 3.11+
MongoDB running locally or Atlas URI
Redis running locally
Groq API key (free at console.groq.com)
```

### Installation

```bash
# Clone the repository
git clone https://github.com/ahmed-1818/skillbridge-ai-layer.git
cd skillbridge-ai-layer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file in the root:

```env
GROQ_API_KEY=your_groq_api_key_here
MONGODB_URI=mongodb://localhost:27017/skillbridge
REDIS_URL=redis://localhost:6379
LLM_MODEL=llama-3.3-70b-versatile
FALLBACK_MODEL=llama-3.1-8b-instant
```

### Run the Server

```bash
uvicorn main:app --reload --port 8000
```

### Test the AI Endpoint

```bash
curl -X POST http://localhost:8000/api/ai/chat \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-123",
    "message": "I need a Python developer for automation",
    "clientId": "user-456",
    "clientName": "Test Client"
  }'
```

---

## 🔑 Key Numbers

| Metric | Value |
|--------|-------|
| Skills in database | 185 |
| LLM response time | < 800ms |
| Negotiation budget tolerance | 20% |
| LLM parameters | 70 Billion |
| Pipeline stages | 5 |
| Security layers | 4 |
| Short-term memory TTL | 2 hours |
| Long-term memory TTL | 30 days |
| Max candidates for LLM ranking | 20 |
| Final matches returned | Top 5 |

---

## 🧪 Testing

The AI layer has been validated through structured QA testing covering:

- ✅ Vulgarity filter — profanity ignored, user redirected
- ✅ PII blocking — phone/email blocked with safety banner
- ✅ Jailbreak guard — stays in persona, redirects to hiring
- ✅ Beginner persona — one question at a time, simple language
- ✅ Advanced persona — technical confidence, skips basic questions
- ✅ Four Pillars Hard Gate — match impossible without all 4 fields
- ✅ Invalid input handling — graceful, no crash, no hallucination
- ✅ Hire intent detection — natural language hire trigger
- ✅ Session memory — Redis continuity across conversation turns
- ✅ Long-term memory — MongoDB recall across sessions

---

## 🏆 Innovation Points

1. **Grounded Skill Extraction** — Passing 185 DB skills to LLM prevents hallucinated tech stacks
2. **Autonomous Negotiation Agent** — AI makes real financial decisions based on client-defined logic
3. **Persona-Driven Prompting** — System prompt changes in real time based on user vocabulary
4. **Hard Gate Validation** — Business rule enforced in code, not just prompts
5. **Real-Time Quality Scoring** — Freelancer replies scored during negotiation for smarter deal-closing

---

## 👨‍💻 Author

**Ahmed Raza**  
AI Engineer — SkillBridge FYP  
GCU Lahore, Pakistan  

- GitHub: [github.com/ahmed-1818](https://github.com/ahmed-1818)
- LinkedIn: [linkedin.com/in/ahmed-raza-ajmal-a11706320](https://linkedin.com/in/ahmed-raza-ajmal-a11706320)
- Email: ahmedrazaajmal56@gmail.com

---

## 📄 License

This project was developed as a Final Year Project at Government College University Lahore.  
© 2025 Ahmed Raza — All rights reserved.
