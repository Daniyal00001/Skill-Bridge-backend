import { ProjectRequirements, FreelancerProfile, MatchedFreelancer } from '../shared/agent.types'

export class RankingEngine {
    rank(freelancers: FreelancerProfile[], project: Partial<ProjectRequirements>): MatchedFreelancer[] {
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