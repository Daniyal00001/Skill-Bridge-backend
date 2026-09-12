# SkillBridge — Backend

SkillBridge is an AI-powered freelance marketplace that helps clients find suitable freelancers, define project requirements, negotiate, and manage projects through a streamlined workflow.

## 🤖 Autonomous AI Agent

The core of SkillBridge includes an **autonomous AI agent** designed to assist with the hiring process. Instead of requiring the client to manually perform every step, the agent analyzes the conversation, understands project requirements, recommends suitable freelancers, assists with negotiation, and helps move the project toward an agreement.

### AI Workflow

```text
Client Conversation
        ↓
Understand Requirements
        ↓
Analyze Project Scope
        ↓
Find & Match Freelancers
        ↓
Compare / Recommend
        ↓
Assist with Negotiation
        ↓
Agreement / Contract
        ↓
Project Management
```

The AI can adapt its interaction based on the user's requirements and assist throughout the hiring journey.

## ⚙️ Backend Features

* User authentication & authorization
* Client, Freelancer & Admin roles
* Project creation and management
* AI-assisted project scoping
* Intelligent freelancer matching
* Proposals and bidding
* AI-assisted negotiation
* Real-time communication with Socket.IO
* Stripe-based payments
* Project and revision management
* Reviews and ratings
* Admin and dispute management

## 🛠️ Tech Stack

**Node.js · Express.js · TypeScript · Prisma · MongoDB · Redis · JWT · Socket.IO · Stripe**

## 🔄 Marketplace Workflow

```text
Client
  ↓
Create Project
  ↓
AI Project Scoping
  ↓
Freelancer Matching
  ↓
Proposal / Selection
  ↓
Chat & Negotiation
  ↓
Agreement
  ↓
Payment
  ↓
Project
  ↓
Submission & Revisions
  ↓
Completion & Review
```

The backend provides the APIs and services that power the SkillBridge marketplace, AI-assisted hiring workflow, real-time communication, payments, and project lifecycle.
