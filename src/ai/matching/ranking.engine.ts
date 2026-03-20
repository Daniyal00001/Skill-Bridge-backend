import { ProjectRequirements, FreelancerProfile, MatchedFreelancer } from '../shared/agent.types'
import { LLMService } from '../shared/llm.service'

export class RankingEngine {
    private llm = new LLMService()

    async rankWithLLM(
        freelancers: FreelancerProfile[],
        project: Partial<ProjectRequirements>
    ): Promise<MatchedFreelancer[]> {
        try {
            const prompt = `
You are a technical hiring expert ranking freelancers for a project.

PROJECT:
- Type: ${project.projectType}
- Platform: ${project.platform}
- Features: ${project.features?.join(', ')}
- Budget: $${project.budgetMin} - $${project.budgetMax}
- Timeline: ${project.timeline}
- Required Skills: ${project.techPreferences?.join(', ')}
- Expertise Needed: ${project.expertiseNeeded}

FREELANCERS:
${freelancers.map((f, i) => `
${i + 1}. ID: ${f.id}
   Name: ${f.name}
   Skills: ${f.skills.join(', ')}
   Rate: $${f.hourlyRate}/hr
   Location: ${f.location}
`).join('')}

Rank these freelancers from BEST to WORST for this project.
For each, give a score 0-100 and a brief reason.

RETURN STRICT JSON ONLY:
[
  {
    "id": "freelancer_id",
    "matchScore": 85,
    "matchReason": "Perfect skill match for Flutter + Firebase project"
  }
]`

            const raw = await this.llm.call([{ role: 'user', content: prompt }])
            const cleaned = raw.replace(/```json/gi, '').replace(/```/g, '').trim()
            const rankings = JSON.parse(cleaned) as { id: string; matchScore: number; matchReason: string }[]

            // Map rankings back to freelancer profiles
            const ranked: MatchedFreelancer[] = rankings
                .map(r => {
                    const freelancer = freelancers.find(f => f.id === r.id)
                    if (!freelancer) return null
                    return {
                        ...freelancer,
                        matchScore: r.matchScore,
                        matchReason: r.matchReason,
                        estimatedTotal: freelancer.hourlyRate ? Math.round(freelancer.hourlyRate * 160) : 0
                    }
                })
                .filter(Boolean) as MatchedFreelancer[]

            return ranked.slice(0, 5)

        } catch (error) {
            console.error('❌ LLM ranking failed, using algorithmic fallback')
            return this.algorithmicRank(freelancers, project)
        }
    }

    // ── Fallback algorithmic ranking ──────────────────────────
    private algorithmicRank(
        freelancers: FreelancerProfile[],
        project: Partial<ProjectRequirements>
    ): MatchedFreelancer[] {
        return freelancers
            .map(f => ({
                ...f,
                matchScore: this.calculateScore(f, project),
                matchReason: this.buildReason(f, project),
                estimatedTotal: f.hourlyRate ? Math.round(f.hourlyRate * 160) : 0,
            }))
            .sort((a, b) => b.matchScore - a.matchScore)
            .slice(0, 5)
    }

    // Keep old rank() for backward compatibility
    rank(freelancers: FreelancerProfile[], project: Partial<ProjectRequirements>): MatchedFreelancer[] {
        return this.algorithmicRank(freelancers, project)
    }

    private calculateScore(f: FreelancerProfile, p: Partial<ProjectRequirements>): number {
        let score = 0
        const techPrefs = p.techPreferences ?? []
        if (techPrefs.length > 0) {
            const matched = techPrefs.filter(s => f.skills.map(x => x.toLowerCase()).includes(s.toLowerCase()))
            score += (matched.length / techPrefs.length) * 50
        } else { score += 25 }

        const min = p.budgetMin ?? null
        const max = p.budgetMax ?? null
        if (min !== null && max !== null && f.hourlyRate) {
            const est = f.hourlyRate * 160
            if (est >= min && est <= max) score += 30
            else if (est < min) score += 20
            else score += 5
        } else { score += 15 }

        score += 10
        return Math.round(score)
    }

    private buildReason(f: FreelancerProfile, p: Partial<ProjectRequirements>): string {
        const reasons: string[] = []
        const techPrefs = p.techPreferences ?? []
        const matched = techPrefs.filter(s => f.skills.map(x => x.toLowerCase()).includes(s.toLowerCase()))
        if (matched.length > 0) reasons.push(`Skilled in ${matched.join(', ')}`)
        if (f.hourlyRate) reasons.push(`$${f.hourlyRate}/hr`)
        if (f.location) reasons.push(f.location)
        return reasons.join(' · ') || 'Good general match'
    }
}