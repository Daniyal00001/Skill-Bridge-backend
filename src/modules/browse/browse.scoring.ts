// import {
//   FreelancerSnapshot,
//   RawProject,
//   SCORING_WEIGHTS,
// } from "./browse.types";

// // ── Returned by scoreProject ────────────────────────────────────
// export interface ProjectScore {
//   score: number;
//   matchPercentage: number;
//   isExploration: boolean;
//   scoreBreakdown: {
//     skillMatch: number;
//     freshness: number;
//     competition: number;
//     budgetFit: number;
//     clientTrust: number;
//     freelancerSuccess: number;
//     activity: number;
//     personalBoost: number;
//   };
// }

// // ── MAIN EXPORT ─────────────────────────────────────────────────
// export function scoreProject(
//   project: RawProject,
//   freelancer: FreelancerSnapshot,
// ): ProjectScore {
//   // ── 1. Skill Match ──────────────────────────────────────────
//   const projectSkillNames = (project.skills ?? []).map((s) =>
//     s.skill.name.toLowerCase(),
//   );
//   const freelancerSkillNames = (freelancer.skillNames ?? []).map((s) =>
//     s.toLowerCase(),
//   );

//   let skillMatch = 0;
//   if (projectSkillNames.length > 0) {
//     const matched = projectSkillNames.filter((s) =>
//       freelancerSkillNames.includes(s),
//     ).length;
//     skillMatch = Math.round((matched / projectSkillNames.length) * 100);
//   }

//   // ── 2. Freshness ────────────────────────────────────────────
//   const ageMs = Date.now() - new Date(project.createdAt).getTime();
//   const ageDays = ageMs / 86_400_000;
//   const freshness = Math.max(0, Math.round(100 - (ageDays / 30) * 100));

//   // ── 3. Competition ──────────────────────────────────────────
//   const MAX_PROPOSALS = 50;
//   const cappedProposals = Math.min(project.proposalCount, MAX_PROPOSALS);
//   const competition = Math.max(
//     0,
//     Math.round(((MAX_PROPOSALS - cappedProposals) / MAX_PROPOSALS) * 100),
//   );

//   // ── 4. Budget Fit ───────────────────────────────────────────
//   let budgetFit = 50;
//   if (
//     freelancer.preferredBudgetMin != null &&
//     freelancer.preferredBudgetMax != null
//   ) {
//     const mid =
//       (freelancer.preferredBudgetMin + freelancer.preferredBudgetMax) / 2;
//     const range =
//       freelancer.preferredBudgetMax - freelancer.preferredBudgetMin || 1;
//     const distance = Math.abs(project.budget - mid);
//     budgetFit = Math.max(0, Math.round(100 - (distance / range) * 100));
//   } else if (freelancer.hourlyRate != null) {
//     const rough =
//       Math.min(1, project.budget / (freelancer.hourlyRate * 40)) * 100;
//     budgetFit = Math.round(rough);
//   }

//   // ── 5. Client Trust ─────────────────────────────────────────
//   let clientTrust = 40;
//   if (project.client) {
//     if (project.client.isVerified) {
//       clientTrust += 30;
//     }
//     if (project.client.averageRating != null) {
//       const ratingPoints = Math.round((project.client.averageRating / 5) * 20);
//       clientTrust += ratingPoints;
//     }
//     if (project.client.hireRate != null) {
//       const hirePoints = Math.round(project.client.hireRate * 10);
//       clientTrust += hirePoints;
//     }
//   }
//   clientTrust = Math.min(100, clientTrust);

//   // ── 6. Freelancer Success ───────────────────────────────────
//   let freelancerSuccess = 40;

//   const contractPoints = Math.min(40, freelancer.completedContracts * 4);
//   freelancerSuccess += contractPoints;

//   if (freelancer.averageRating != null) {
//     const ratingPoints = Math.round((freelancer.averageRating / 5) * 10);
//     freelancerSuccess += ratingPoints;
//   }

//   freelancerSuccess = Math.max(0, Math.min(100, freelancerSuccess));

//   // ── 7. Activity ─────────────────────────────────────────────
//   const recentActivityPenalty =
//     Math.min(freelancer.recentProposalCount, 20) * 2;
//   const activity = Math.max(0, 100 - recentActivityPenalty);

//   // ── 8. Personal Boost ───────────────────────────────────────
//   let personalBoost = 0;

//   const inPreferredCategory =
//     project.category?.slug &&
//     freelancer.preferredCategories.includes(project.category.slug);
//   if (inPreferredCategory) {
//     personalBoost += 0.15;
//   }

//   if (freelancer.savedProjectIds.includes(project.id)) {
//     personalBoost += 0.1;
//   }

//   if (freelancer.viewedProjectIds.includes(project.id)) {
//     personalBoost -= 0.05;
//   }

//   // ── Weighted Final Score ────────────────────────────────────
//   const weighted =
//     skillMatch * SCORING_WEIGHTS.skillMatch +
//     freshness * SCORING_WEIGHTS.freshness +
//     competition * SCORING_WEIGHTS.competition +
//     budgetFit * SCORING_WEIGHTS.budgetFit +
//     clientTrust * SCORING_WEIGHTS.clientTrust +
//     freelancerSuccess * SCORING_WEIGHTS.freelancerSuccess +
//     activity * SCORING_WEIGHTS.activity;

//   const boosted = weighted * (1 + personalBoost);
//   const score = Math.min(100, Math.round(boosted));

//   return {
//     score,
//     matchPercentage: skillMatch,
//     isExploration: false,
//     scoreBreakdown: {
//       skillMatch,
//       freshness,
//       competition,
//       budgetFit,
//       clientTrust,
//       freelancerSuccess,
//       activity,
//       personalBoost,
//     },
//   };
// }

import {
  FreelancerSnapshot,
  RawProject,
  SCORING_WEIGHTS,
} from "./browse.types";

// ── Returned by scoreProject ────────────────────────────────────
export interface ProjectScore {
  score: number;
  matchPercentage: number;
  isExploration: boolean;
  scoreBreakdown: {
    skillMatch: number;
    freshness: number;
    competition: number;
    budgetFit: number;
    clientTrust: number;
    freelancerSuccess: number;
    activity: number;
    personalBoost: number;
  };
}

// ── Console Helpers ─────────────────────────────────────────────
// Styles for browser console (ignored gracefully in Node)
const S = {
  header:
    "color:#fff;background:#1a1a2e;padding:3px 8px;border-radius:4px;font-weight:bold;font-size:13px;",
  section: "color:#e94560;font-weight:bold;font-size:12px;",
  label: "color:#a8dadc;font-weight:600;",
  value: "color:#f1faee;",
  score: "color:#06d6a0;font-weight:bold;font-size:13px;",
  warn: "color:#ffd166;font-weight:600;",
  muted: "color:#6c757d;",
  divider: "color:#333;",
};

function logSection(title: string) {
  console.log(`%c── ${title} ──`, S.section);
}

function logKV(label: string, value: unknown, style = S.value) {
  console.log(`%c  ${label}:%c`, S.label, style, value);
}

function logScore(label: string, value: number) {
  const bar =
    "█".repeat(Math.round(value / 10)) +
    "░".repeat(10 - Math.round(value / 10));
  console.log(
    `%c  ${label.padEnd(22)}%c ${String(value).padStart(3)}/100  %c${bar}`,
    S.label,
    S.score,
    S.muted,
  );
}

// ── MAIN EXPORT ─────────────────────────────────────────────────
export function scoreProject(
  project: RawProject,
  freelancer: FreelancerSnapshot,
): ProjectScore {
  // ════════════════════════════════════════════════════════════════
  // 📥 INPUTS
  // ════════════════════════════════════════════════════════════════
  console.group(`%c🔢 scoreProject()  →  "${project.title}"`, S.header);

  console.group("%c📥 INPUTS", "color:#4cc9f0;font-weight:bold;");

  console.group("%cProject", S.label);
  logKV("id", project.id);
  logKV("title", project.title);
  logKV("status", project.status);
  logKV("budget", `$${project.budget} (${project.budgetType})`);
  logKV("deadline", project.deadline);
  logKV("createdAt", project.createdAt);
  logKV("proposalCount", project.proposalCount);
  logKV("experienceLevel", project.experienceLevel);
  logKV("size", project.size);
  logKV("category", project.category);
  logKV(
    "skills",
    project.skills.map((s) => s.skill.name),
  );
  console.group("%cClient", S.label);
  console.table(project.client);
  console.groupEnd();
  console.groupEnd();

  console.group("%cFreelancer", S.label);
  logKV("id", freelancer.id);
  logKV("skillNames", freelancer.skillNames);
  logKV("experienceLevel", freelancer.experienceLevel);
  logKV(
    "hourlyRate",
    freelancer.hourlyRate != null ? `$${freelancer.hourlyRate}/hr` : "—",
  );
  logKV("profileCompletionScore", `${freelancer.profileCompletionScore}%`);
  logKV("completedContracts", freelancer.completedContracts);
  logKV("averageRating", freelancer.averageRating ?? "—");
  logKV("recentProposalCount", freelancer.recentProposalCount);
  logKV("lastLoginAt", freelancer.lastLoginAt);
  logKV("preferredCategories", freelancer.preferredCategories);
  logKV("appliedProjectIds", freelancer.appliedProjectIds);
  logKV("savedProjectIds", freelancer.savedProjectIds);
  logKV("viewedProjectIds", freelancer.viewedProjectIds);
  console.groupEnd();

  console.groupEnd(); // INPUTS

  // ════════════════════════════════════════════════════════════════
  // ⚙️  DIMENSION CALCULATIONS
  // ════════════════════════════════════════════════════════════════
  console.group(
    "%c⚙️  DIMENSION CALCULATIONS",
    "color:#f8961e;font-weight:bold;",
  );

  // ── 1. Skill Match ──────────────────────────────────────────
  logSection("1. Skill Match");
  const projectSkillNames = (project.skills ?? []).map((s) =>
    s.skill.name.toLowerCase(),
  );
  const freelancerSkillNames = (freelancer.skillNames ?? []).map((s) =>
    s.toLowerCase(),
  );
  logKV("projectSkillNames", projectSkillNames);
  logKV("freelancerSkillNames", freelancerSkillNames);

  let skillMatch = 0;
  if (projectSkillNames.length > 0) {
    const matched = projectSkillNames.filter((s) =>
      freelancerSkillNames.includes(s),
    ).length;
    skillMatch = Math.round((matched / projectSkillNames.length) * 100);
    logKV("matched skills", matched);
    logKV("total required", projectSkillNames.length);
    logKV("formula", `round((${matched} / ${projectSkillNames.length}) × 100)`);
  } else {
    console.log(
      "%c  No required skills on project → skillMatch stays 0",
      S.warn,
    );
  }
  logScore("skillMatch", skillMatch);

  // ── 2. Freshness ────────────────────────────────────────────
  logSection("2. Freshness");
  const ageMs = Date.now() - new Date(project.createdAt).getTime();
  const ageDays = ageMs / 86_400_000;
  const freshness = Math.max(0, Math.round(100 - (ageDays / 30) * 100));
  logKV("now (ms)", Date.now());
  logKV("createdAt (ms)", new Date(project.createdAt).getTime());
  logKV("ageMs", ageMs);
  logKV("ageDays", ageDays.toFixed(4));
  logKV("formula", `max(0, round(100 - (${ageDays.toFixed(4)} / 30) × 100))`);
  logScore("freshness", freshness);

  // ── 3. Competition ──────────────────────────────────────────
  logSection("3. Competition");
  const MAX_PROPOSALS = 50;
  const cappedProposals = Math.min(project.proposalCount, MAX_PROPOSALS);
  const competition = Math.max(
    0,
    Math.round(((MAX_PROPOSALS - cappedProposals) / MAX_PROPOSALS) * 100),
  );
  logKV("proposalCount", project.proposalCount);
  logKV("MAX_PROPOSALS", MAX_PROPOSALS);
  logKV("cappedProposals", cappedProposals);
  logKV(
    "formula",
    `max(0, round(((${MAX_PROPOSALS} - ${cappedProposals}) / ${MAX_PROPOSALS}) × 100))`,
  );
  logScore("competition", competition);

  // ── 4. Budget Fit ───────────────────────────────────────────
  logSection("4. Budget Fit");
  let budgetFit = 50;
  if (
    freelancer.preferredBudgetMin != null &&
    freelancer.preferredBudgetMax != null
  ) {
    const mid =
      (freelancer.preferredBudgetMin + freelancer.preferredBudgetMax) / 2;
    const range =
      freelancer.preferredBudgetMax - freelancer.preferredBudgetMin || 1;
    const distance = Math.abs(project.budget - mid);
    budgetFit = Math.max(0, Math.round(100 - (distance / range) * 100));
    logKV("path", "preferredBudget range");
    logKV("mid", mid);
    logKV("range", range);
    logKV("distance", distance);
    logKV("formula", `max(0, round(100 - (${distance} / ${range}) × 100))`);
  } else if (freelancer.hourlyRate != null) {
    const rough =
      Math.min(1, project.budget / (freelancer.hourlyRate * 40)) * 100;
    budgetFit = Math.round(rough);
    logKV("path", "hourlyRate fallback");
    logKV("hourlyRate × 40", freelancer.hourlyRate * 40);
    logKV("rough", rough.toFixed(2));
  } else {
    logKV("path", "no budget info → neutral 50", S.warn);
  }
  logScore("budgetFit", budgetFit);

  // ── 5. Client Trust ─────────────────────────────────────────
  logSection("5. Client Trust");
  let clientTrust = 40;
  logKV("base", 40);
  if (project.client) {
    if (project.client.isVerified) {
      clientTrust += 30;
      logKV("+30 isVerified", clientTrust);
    }
    if (project.client.averageRating != null) {
      const ratingPoints = Math.round((project.client.averageRating / 5) * 20);
      clientTrust += ratingPoints;
      logKV(
        `+${ratingPoints} averageRating (${project.client.averageRating}/5)`,
        clientTrust,
      );
    }
    if (project.client.hireRate != null) {
      const hirePoints = Math.round(project.client.hireRate * 10);
      clientTrust += hirePoints;
      logKV(
        `+${hirePoints} hireRate (${project.client.hireRate})`,
        clientTrust,
      );
    }
  } else {
    console.log("%c  No client data → stays at 40", S.warn);
  }
  clientTrust = Math.min(100, clientTrust);
  logScore("clientTrust", clientTrust);

  // ── 6. Freelancer Success ───────────────────────────────────
  logSection("6. Freelancer Success");
  let freelancerSuccess = 40;
  logKV("base", 40);

  const contractPoints = Math.min(40, freelancer.completedContracts * 4);
  freelancerSuccess += contractPoints;
  logKV(
    `+${contractPoints} completedContracts (${freelancer.completedContracts} × 4, capped 40)`,
    freelancerSuccess,
  );

  if (freelancer.averageRating != null) {
    const ratingPoints = Math.round((freelancer.averageRating / 5) * 10);
    freelancerSuccess += ratingPoints;
    logKV(
      `+${ratingPoints} averageRating (${freelancer.averageRating}/5)`,
      freelancerSuccess,
    );
  }

  freelancerSuccess = Math.max(0, Math.min(100, freelancerSuccess));

  logScore("freelancerSuccess", freelancerSuccess);

  // ── 7. Activity ─────────────────────────────────────────────
  logSection("7. Activity");
  const recentActivityPenalty =
    Math.min(freelancer.recentProposalCount, 20) * 2;
  const activity = Math.max(0, 100 - recentActivityPenalty);
  logKV("recentProposalCount", freelancer.recentProposalCount);
  logKV("recentActivityPenalty", recentActivityPenalty);
  logKV("formula", `max(0, 100 - ${recentActivityPenalty})`);
  logScore("activity", activity);

  // ── 8. Personal Boost ───────────────────────────────────────
  logSection("8. Personal Boost");
  let personalBoost = 0;
  logKV("base", 0);

  const inPreferredCategory =
    project.category?.slug &&
    freelancer.preferredCategories.includes(project.category.slug);
  if (inPreferredCategory) {
    personalBoost += 0.15;
    logKV("+0.15 preferred category match", `"${project.category.slug}"`);
  } else {
    logKV("preferred category match", "❌ none");
  }

  if (freelancer.savedProjectIds.includes(project.id)) {
    personalBoost += 0.1;
    logKV("+0.10 project is saved", project.id);
  }

  if (freelancer.viewedProjectIds.includes(project.id)) {
    personalBoost -= 0.05;
    logKV("-0.05 already viewed", project.id);
  }

  logKV("finalPersonalBoost", personalBoost);
  console.groupEnd(); // DIMENSION CALCULATIONS

  // ════════════════════════════════════════════════════════════════
  // 🧮 WEIGHTED FINAL SCORE
  // ════════════════════════════════════════════════════════════════
  console.group("%c🧮 WEIGHTED FINAL SCORE", "color:#4ade80;font-weight:bold;");

  const weighted =
    skillMatch * SCORING_WEIGHTS.skillMatch +
    freshness * SCORING_WEIGHTS.freshness +
    competition * SCORING_WEIGHTS.competition +
    budgetFit * SCORING_WEIGHTS.budgetFit +
    clientTrust * SCORING_WEIGHTS.clientTrust +
    freelancerSuccess * SCORING_WEIGHTS.freelancerSuccess +
    activity * SCORING_WEIGHTS.activity;

  console.log("%cWeights breakdown:", S.label);
  console.table({
    skillMatch: {
      score: skillMatch,
      weight: SCORING_WEIGHTS.skillMatch,
      contribution: +(skillMatch * SCORING_WEIGHTS.skillMatch).toFixed(2),
    },
    freshness: {
      score: freshness,
      weight: SCORING_WEIGHTS.freshness,
      contribution: +(freshness * SCORING_WEIGHTS.freshness).toFixed(2),
    },
    competition: {
      score: competition,
      weight: SCORING_WEIGHTS.competition,
      contribution: +(competition * SCORING_WEIGHTS.competition).toFixed(2),
    },
    budgetFit: {
      score: budgetFit,
      weight: SCORING_WEIGHTS.budgetFit,
      contribution: +(budgetFit * SCORING_WEIGHTS.budgetFit).toFixed(2),
    },
    clientTrust: {
      score: clientTrust,
      weight: SCORING_WEIGHTS.clientTrust,
      contribution: +(clientTrust * SCORING_WEIGHTS.clientTrust).toFixed(2),
    },
    freelancerSuccess: {
      score: freelancerSuccess,
      weight: SCORING_WEIGHTS.freelancerSuccess,
      contribution: +(
        freelancerSuccess * SCORING_WEIGHTS.freelancerSuccess
      ).toFixed(2),
    },
    activity: {
      score: activity,
      weight: SCORING_WEIGHTS.activity,
      contribution: +(activity * SCORING_WEIGHTS.activity).toFixed(2),
    },
  });

  logKV("weighted (pre-boost)", weighted.toFixed(2));
  logKV("personalBoost", personalBoost);
  logKV(
    "formula",
    `min(100, round(${weighted.toFixed(2)} × (1 + ${personalBoost})))`,
  );

  const boosted = weighted * (1 + personalBoost);
  const score = Math.min(100, Math.round(boosted));

  logKV("boosted", boosted.toFixed(2));
  logKV("🏆 FINAL SCORE", score, S.score);

  console.groupEnd(); // WEIGHTED FINAL SCORE

  // ════════════════════════════════════════════════════════════════
  // 📤 OUTPUT
  // ════════════════════════════════════════════════════════════════
  const result: ProjectScore = {
    score,
    matchPercentage: skillMatch,
    isExploration: false,
    scoreBreakdown: {
      skillMatch,
      freshness,
      competition,
      budgetFit,
      clientTrust,
      freelancerSuccess,
      activity,
      personalBoost,
    },
  };

  console.group("%c📤 OUTPUT", "color:#c77dff;font-weight:bold;");
  console.table({
    score: result.score,
    matchPercentage: result.matchPercentage,
    isExploration: result.isExploration,
    ...result.scoreBreakdown,
  });
  console.groupEnd(); // OUTPUT

  console.groupEnd(); // scoreProject()

  return result;
}
