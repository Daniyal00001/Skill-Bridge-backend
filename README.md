# SkillBridge — Backend

SkillBridge is an AI-powered freelance marketplace that helps clients turn project ideas into complete freelance engagements. The backend powers authentication, project management, freelancer matching, negotiation, contracts, payments, real-time communication, and the AI hiring workflow.

## 🤖 Autonomous AI Agent

The core of SkillBridge is an **autonomous AI hiring agent**. Unlike a traditional chatbot that only responds to messages, the agent understands the client's requirements and can take actions throughout the hiring process.

It analyzes the conversation, extracts the project's **scope, budget, technology requirements, and timeline**, evaluates project feasibility, finds suitable freelancers, ranks them based on skills and experience, communicates with freelancers, assists with negotiation, and moves the project toward an agreement.

### AI Workflow

```text
Client Conversation
        ↓
Understand Requirements
        ↓
Analyze Project
        ↓
Scope + Budget + Tech Stack + Timeline
        ↓
Find & Rank Freelancers
        ↓
AI Outreach
        ↓
Negotiation
        ↓
Agreement
        ↓
Contract Generation
```

The agent adapts its communication according to the client's expertise level. Beginners receive simpler explanations and guided questions, while experienced users can move through the process with fewer clarification steps.

### AI Architecture

The AI system is divided into specialized services:

* **AI Orchestrator** — controls the workflow and decides the next stage
* **Conversation Service** — manages the AI conversation and adapts responses
* **Extraction Service** — extracts structured project requirements from conversations
* **Matching Service** — finds and ranks suitable freelancers
* **Moderation Service** — protects conversations from harmful content, PII, and prompt injection
* **Negotiation Service** — communicates with freelancers and assists in closing deals
* **Scoring Service** — evaluates freelancer suitability
* **Memory System** — maintains short-term conversation and long-term user context
* **Contract Service** — generates the agreement once the deal is finalized

### Five-Stage AI Process

```text
UNDERSTAND → ANALYZE → MATCH → NEGOTIATE → CONTRACT
```

The **Four Pillars — Scope, Budget, Tech Stack, and Timeline — act as a hard gate** before freelancer matching can begin. This ensures the agent has enough information to make meaningful recommendations.

## ⚙️ Backend

The backend provides the APIs and services required for the complete marketplace lifecycle, including:

* Authentication & role-based access
* Client, Freelancer & Admin workflows
* Project and proposal management
* AI-powered freelancer matching
* Real-time communication
* Negotiation and contract workflow
* Stripe payments
* Project and revision management
* Reviews and ratings
* Admin and dispute management

## 🛠️ Tech Stack

**Node.js · Express.js · TypeScript · Prisma · MongoDB · Redis · JWT · Socket.IO · Stripe · AI/LLM**

## 🔄 Marketplace Flow

```text
Client
  ↓
Describe Project
  ↓
AI Understands & Scopes
  ↓
Freelancer Matching
  ↓
Selection & Outreach
  ↓
AI Negotiation
  ↓
Agreement & Contract
  ↓
Payment
  ↓
Project Development
  ↓
Submission & Revisions
  ↓
Completion & Review
```
