// import {
//   RawFreelancer,
//   ClientSnapshot,
//   ScoredFreelancer,
//   FREELANCER_SCORING_WEIGHTS,
// } from "./browseFreelancers.types";

// // ── Console Helpers ─────────────────────────────────────────────
// const S = {
//   header:
//     "color:#fff;background:#1a1a2e;padding:3px 8px;border-radius:4px;font-weight:bold;font-size:13px;",
//   section: "color:#e94560;font-weight:bold;font-size:12px;",
//   label: "color:#a8dadc;font-weight:600;",
//   value: "color:#f1faee;",
//   score: "color:#06d6a0;font-weight:bold;font-size:13px;",
//   warn: "color:#ffd166;font-weight:600;",
//   muted: "color:#6c757d;",
//   divider: "color:#333;",
// };

// function logSection(title: string) {
//   console.log(`%c── ${title} ──`, S.section);
// }

// function logKV(label: string, value: unknown, style = S.value) {
//   console.log(`%c  ${label}:%c`, S.label, style, value);
// }

// function logScore(label: string, value: number) {
//   const bar =
//     "█".repeat(Math.round(value / 10)) +
//     "░".repeat(10 - Math.round(value / 10));
//   console.log(
//     `%c  ${label.padEnd(22)}%c ${String(value).padStart(3)}/100  %c${bar}`,
//     S.label,
//     S.score,
//     S.muted,
//   );
// }

// // ── 1. SKILL MATCH (30%) ─────────────────────────────────────────
// function calcSkillMatch(
//   freelancerSkills: string[],
//   clientRequiredSkills: string[],
// ): number {
//   logSection("1. Skill Match");
//   logKV("freelancerSkills", freelancerSkills);
//   logKV("clientRequiredSkills", clientRequiredSkills);

//   if (!clientRequiredSkills.length) {
//     console.log("%c  No required skills → neutral 60", S.warn);
//     logScore("skillMatch", 60);
//     return 60;
//   }
//   if (!freelancerSkills.length) {
//     console.log("%c  Freelancer has no skills → 0", S.warn);
//     logScore("skillMatch", 0);
//     return 0;
//   }

//   const freelancerSet = new Set(freelancerSkills.map((s) => s.toLowerCase()));
//   const matched = clientRequiredSkills.filter((s) =>
//     freelancerSet.has(s.toLowerCase()),
//   ).length;

//   const result = Math.round((matched / clientRequiredSkills.length) * 100);
//   logKV("matched", matched);
//   logKV("total required", clientRequiredSkills.length);
//   logKV(
//     "formula",
//     `round((${matched} / ${clientRequiredSkills.length}) × 100)`,
//   );
//   logScore("skillMatch", result);
//   return result;
// }

// // ── 2. RATING SCORE (25%) ────────────────────────────────────────
// function calcRatingScore(
//   averageRating?: number | null,
//   totalReviews?: number,
// ): number {
//   logSection("2. Rating Score");
//   logKV("averageRating", averageRating ?? "—");
//   logKV("totalReviews", totalReviews ?? 0);

//   if (!averageRating) {
//     console.log("%c  No rating → neutral 40", S.warn);
//     logScore("rating", 40);
//     return 40;
//   }

//   const base = (Math.min(averageRating, 5) / 5) * 90;
//   const volumeBonus = Math.min((totalReviews ?? 0) / 20, 1) * 10;
//   const result = Math.round(Math.min(100, base + volumeBonus));

//   logKV("base (rating/5 × 90)", base.toFixed(2));
//   logKV("volumeBonus (reviews/20 × 10, capped)", volumeBonus.toFixed(2));
//   logKV(
//     "formula",
//     `min(100, round(${base.toFixed(2)} + ${volumeBonus.toFixed(2)}))`,
//   );
//   logScore("rating", result);
//   return result;
// }

// // ── 3. AVAILABILITY SCORE (20%) ──────────────────────────────────
// function calcAvailabilityScore(
//   availability: "AVAILABLE" | "BUSY" | "UNAVAILABLE",
// ): number {
//   logSection("3. Availability Score");
//   logKV("availability", availability);

//   let result: number;
//   switch (availability) {
//     case "AVAILABLE":
//       result = 100;
//       break;
//     case "BUSY":
//       result = 40;
//       break;
//     case "UNAVAILABLE":
//       result = 0;
//       break;
//     default:
//       result = 0;
//   }

//   logKV("mapped score", result);
//   logScore("availability", result);
//   return result;
// }

// // ── 4. BUDGET FIT SCORE (10%) ────────────────────────────────────
// function calcBudgetFit(
//   freelancerHourlyRate?: number | null,
//   client?: Pick<ClientSnapshot, "hourlyBudgetMin" | "hourlyBudgetMax">,
// ): number {
//   logSection("4. Budget Fit");
//   logKV(
//     "freelancerHourlyRate",
//     freelancerHourlyRate != null ? `$${freelancerHourlyRate}/hr` : "—",
//   );
//   logKV(
//     "client.hourlyBudgetMin",
//     client?.hourlyBudgetMin != null ? `$${client.hourlyBudgetMin}` : "—",
//   );
//   logKV(
//     "client.hourlyBudgetMax",
//     client?.hourlyBudgetMax != null ? `$${client.hourlyBudgetMax}` : "—",
//   );

//   if (!freelancerHourlyRate) {
//     console.log("%c  No hourly rate → neutral 50", S.warn);
//     logScore("budgetFit", 50);
//     return 50;
//   }
//   if (!client?.hourlyBudgetMin && !client?.hourlyBudgetMax) {
//     console.log("%c  No client budget range → neutral 50", S.warn);
//     logScore("budgetFit", 50);
//     return 50;
//   }

//   const min = client.hourlyBudgetMin ?? 0;
//   const max = client.hourlyBudgetMax ?? Infinity;
//   logKV("effective min", min);
//   logKV("effective max", max === Infinity ? "∞" : max);

//   let result: number;

//   if (freelancerHourlyRate >= min && freelancerHourlyRate <= max) {
//     result = 100;
//     logKV("path", "✅ within range → 100");
//   } else if (freelancerHourlyRate > max) {
//     const overage = freelancerHourlyRate - max;
//     result = Math.max(0, Math.round(100 - (overage / max) * 100));
//     logKV("path", "too expensive");
//     logKV("overage", overage);
//     logKV("formula", `max(0, round(100 - (${overage} / ${max}) × 100))`);
//   } else {
//     const underage = min - freelancerHourlyRate;
//     result = Math.max(0, Math.round(100 - (underage / min) * 100));
//     logKV("path", "too cheap");
//     logKV("underage", underage);
//     logKV("formula", `max(0, round(100 - (${underage} / ${min}) × 100))`);
//   }

//   logScore("budgetFit", result);
//   return result;
// }

// // ── 5. SUCCESS SCORE (10%) ───────────────────────────────────────
// function calcSuccessScore(
//   freelancer: Pick<
//     RawFreelancer,
//     "completedContracts" | "profileCompletionScore"
//   >,
// ): number {
//   logSection("5. Success Score");
//   logKV("completedContracts", freelancer.completedContracts);
//   logKV("profileCompletionScore", `${freelancer.profileCompletionScore}%`);

//   let score = 30;
//   logKV("base", 30);

//   const contractPoints = Math.min(freelancer.completedContracts, 15) * 3;
//   score += contractPoints;
//   logKV(
//     `+${contractPoints} completedContracts (${freelancer.completedContracts} × 3, capped 15)`,
//     score,
//   );

//   const profilePoints =
//     (Math.min(freelancer.profileCompletionScore, 100) / 100) * 35;
//   score += profilePoints;
//   logKV(
//     `+${profilePoints.toFixed(2)} profileCompletion (${freelancer.profileCompletionScore}/100 × 35)`,
//     score.toFixed(2),
//   );

//   const result = Math.round(Math.max(0, Math.min(100, score)));
//   logKV("formula", `max(0, min(100, round(${score.toFixed(2)})))`);
//   logScore("successScore", result);
//   return result;
// }

// // ── 6. ACTIVITY SCORE (5% - Last Login) ─────────────────────────
// function calcActivityScore(lastLoginAt?: Date | null): number {
//   logSection("6. Activity Score");
//   logKV("lastLoginAt", lastLoginAt ?? "—");

//   if (!lastLoginAt) {
//     console.log("%c  No login data → 30", S.warn);
//     logScore("activityScore", 30);
//     return 30;
//   }

//   const daysSinceLogin =
//     (Date.now() - new Date(lastLoginAt).getTime()) / 86_400_000;
//   const result = Math.round(Math.max(0, 100 - (daysSinceLogin / 30) * 100));

//   logKV("daysSinceLogin", daysSinceLogin.toFixed(4));
//   logKV(
//     "formula",
//     `max(0, round(100 - (${daysSinceLogin.toFixed(4)} / 30) × 100))`,
//   );
//   logScore("activityScore", result);
//   return result;
// }

// // ── 7. PERSONAL BOOST (multiplier) ──────────────────────────────
// function calcPersonalBoost(
//   freelancer: RawFreelancer,
//   client: ClientSnapshot,
// ): number {
//   logSection("7. Personal Boost");
//   let boost = 1.0;
//   logKV("base boost", boost);

//   if (client.viewedFreelancerIds.includes(freelancer.id)) {
//     boost -= 0.05;
//     logKV("-0.05 already viewed", freelancer.id);
//   } else {
//     logKV("viewed", "❌ not viewed");
//   }

//   if (client.hiredFreelancerIds.includes(freelancer.id)) {
//     boost -= 0.15;
//     logKV("-0.15 previously hired", freelancer.id);
//   } else {
//     logKV("previously hired", "❌ no");
//   }

//   if (
//     client.preferredRegion &&
//     freelancer.region &&
//     client.preferredRegion.toLowerCase() === freelancer.region.toLowerCase()
//   ) {
//     boost += 0.08;
//     logKV("+0.08 region match", `"${freelancer.region}"`);
//   } else {
//     logKV("region match", "❌ none");
//   }

//   if (
//     client.preferredExpLevel &&
//     freelancer.experienceLevel === client.preferredExpLevel
//   ) {
//     boost += 0.07;
//     logKV("+0.07 experience level match", freelancer.experienceLevel);
//   } else {
//     logKV("experience level match", "❌ none");
//   }

//   // Language match boost
//   const freelancerLangs = (freelancer.languages as any[]) || [];
//   const freelancerLangNames = new Set(
//     freelancerLangs.map((l: any) => (l.name || l).toLowerCase()),
//   );

//   let langMatched = false;
//   if (
//     client.preferredLanguage &&
//     freelancerLangNames.has(client.preferredLanguage.toLowerCase())
//   ) {
//     boost += 0.05;
//     langMatched = true;
//     logKV("+0.05 preferred language match", client.preferredLanguage);
//   }

//   const commonLangs = client.spokenLanguages.filter((l) =>
//     freelancerLangNames.has(l.toLowerCase()),
//   );
//   if (commonLangs.length > 0) {
//     boost += 0.03 * Math.min(commonLangs.length, 2);
//     langMatched = true;
//     logKV(
//       `+${0.03 * Math.min(commonLangs.length, 2)} communication boost`,
//       commonLangs.join(", "),
//     );
//   }

//   if (!langMatched) {
//     logKV("language match", "❌ none");
//   }

//   const result = Math.min(Math.max(boost, 0.5), 1.25);
//   logKV("finalBoost (clamped 0.5–1.25)", result);
//   return result;
// }

// // ── MASTER SCORER ────────────────────────────────────────────────
// export function scoreFreelancer(
//   freelancer: RawFreelancer,
//   client: ClientSnapshot,
// ): Omit<ScoredFreelancer, keyof RawFreelancer> {
//   // ════════════════════════════════════════════════════════════════
//   // 📥 INPUTS
//   // ════════════════════════════════════════════════════════════════
//   console.group(
//     `%c🔢 scoreFreelancer()  →  "${freelancer.fullName}"`,
//     S.header,
//   );

//   console.group("%c📥 INPUTS", "color:#4cc9f0;font-weight:bold;");

//   console.group("%cFreelancer", S.label);
//   logKV("id", freelancer.id);
//   logKV("fullName", freelancer.fullName);
//   logKV("availability", freelancer.availability);
//   logKV("experienceLevel", freelancer.experienceLevel);
//   logKV(
//     "hourlyRate",
//     freelancer.hourlyRate != null ? `$${freelancer.hourlyRate}/hr` : "—",
//   );
//   logKV("averageRating", freelancer.averageRating ?? "—");
//   logKV("totalReviews", freelancer.totalReviews);
//   logKV("completedContracts", freelancer.completedContracts);
//   logKV("profileCompletionScore", `${freelancer.profileCompletionScore}%`);
//   logKV("region", freelancer.region ?? "—");
//   logKV("lastLoginAt", freelancer.lastLoginAt ?? "—");
//   logKV(
//     "skills",
//     freelancer.skills.map((s) => s.skill.name),
//   );
//   console.groupEnd();

//   console.group("%cClient", S.label);
//   logKV("requiredSkills", client.requiredSkills);
//   logKV("preferredExpLevel", client.preferredExpLevel ?? "—");
//   logKV("preferredRegion", client.preferredRegion ?? "—");
//   logKV(
//     "hourlyBudget",
//     client.hourlyBudgetMin != null
//       ? `$${client.hourlyBudgetMin} – $${client.hourlyBudgetMax}`
//       : "—",
//   );
//   logKV("viewedFreelancerIds", client.viewedFreelancerIds);
//   logKV("hiredFreelancerIds", client.hiredFreelancerIds);
//   console.groupEnd();

//   console.groupEnd(); // INPUTS

//   // ════════════════════════════════════════════════════════════════
//   // ⚙️  DIMENSION CALCULATIONS
//   // ════════════════════════════════════════════════════════════════
//   console.group(
//     "%c⚙️  DIMENSION CALCULATIONS",
//     "color:#f8961e;font-weight:bold;",
//   );

//   const freelancerSkillNames = freelancer.skills.map((s) => s.skill.name);

//   const skillMatch = calcSkillMatch(
//     freelancerSkillNames,
//     client.requiredSkills,
//   );
//   const rating = calcRatingScore(
//     freelancer.averageRating,
//     freelancer.totalReviews,
//   );
//   const availability = calcAvailabilityScore(freelancer.availability);
//   const budgetFit = calcBudgetFit(freelancer.hourlyRate, client);
//   const successScore = calcSuccessScore(freelancer);
//   const activityScore = calcActivityScore(freelancer.lastLoginAt);
//   const personalBoost = calcPersonalBoost(freelancer, client);

//   console.groupEnd(); // DIMENSION CALCULATIONS

//   // ════════════════════════════════════════════════════════════════
//   // 🧮 WEIGHTED FINAL SCORE
//   // ════════════════════════════════════════════════════════════════
//   console.group("%c🧮 WEIGHTED FINAL SCORE", "color:#4ade80;font-weight:bold;");

//   const weighted =
//     skillMatch * FREELANCER_SCORING_WEIGHTS.skillMatch +
//     rating * FREELANCER_SCORING_WEIGHTS.rating +
//     availability * FREELANCER_SCORING_WEIGHTS.availability +
//     budgetFit * FREELANCER_SCORING_WEIGHTS.budgetFit +
//     successScore * FREELANCER_SCORING_WEIGHTS.successScore +
//     activityScore * FREELANCER_SCORING_WEIGHTS.activityScore;

//   console.log("%cWeights breakdown:", S.label);
//   console.table({
//     skillMatch: {
//       score: skillMatch,
//       weight: FREELANCER_SCORING_WEIGHTS.skillMatch,
//       contribution: +(
//         skillMatch * FREELANCER_SCORING_WEIGHTS.skillMatch
//       ).toFixed(2),
//     },
//     rating: {
//       score: rating,
//       weight: FREELANCER_SCORING_WEIGHTS.rating,
//       contribution: +(rating * FREELANCER_SCORING_WEIGHTS.rating).toFixed(2),
//     },
//     availability: {
//       score: availability,
//       weight: FREELANCER_SCORING_WEIGHTS.availability,
//       contribution: +(
//         availability * FREELANCER_SCORING_WEIGHTS.availability
//       ).toFixed(2),
//     },
//     budgetFit: {
//       score: budgetFit,
//       weight: FREELANCER_SCORING_WEIGHTS.budgetFit,
//       contribution: +(budgetFit * FREELANCER_SCORING_WEIGHTS.budgetFit).toFixed(
//         2,
//       ),
//     },
//     successScore: {
//       score: successScore,
//       weight: FREELANCER_SCORING_WEIGHTS.successScore,
//       contribution: +(
//         successScore * FREELANCER_SCORING_WEIGHTS.successScore
//       ).toFixed(2),
//     },
//     activityScore: {
//       score: activityScore,
//       weight: FREELANCER_SCORING_WEIGHTS.activityScore,
//       contribution: +(
//         activityScore * FREELANCER_SCORING_WEIGHTS.activityScore
//       ).toFixed(2),
//     },
//   });

//   logKV("weighted (pre-boost)", weighted.toFixed(2));
//   logKV("personalBoost multiplier", personalBoost);
//   logKV(
//     "formula",
//     `min(100, round(${weighted.toFixed(2)} × ${personalBoost}))`,
//   );

//   const score = Math.round(Math.min(100, weighted * personalBoost));

//   logKV("🏆 FINAL SCORE", score, S.score);

//   console.groupEnd(); // WEIGHTED FINAL SCORE

//   // ════════════════════════════════════════════════════════════════
//   // 📤 OUTPUT
//   // ════════════════════════════════════════════════════════════════
//   const result: Omit<ScoredFreelancer, keyof RawFreelancer> = {
//     score,
//     matchPercentage: skillMatch,
//     isExploration: false,
//     scoreBreakdown: {
//       skillMatch,
//       rating,
//       availability,
//       budgetFit,
//       successScore,
//       activityScore,
//       profileScore: freelancer.profileCompletionScore,
//     },
//   };

//   console.group("%c📤 OUTPUT", "color:#c77dff;font-weight:bold;");
//   console.table({
//     score: result.score,
//     matchPercentage: result.matchPercentage,
//     isExploration: result.isExploration,
//     ...result.scoreBreakdown,
//   });
//   console.groupEnd(); // OUTPUT

//   console.groupEnd(); // scoreFreelancer()

//   return result;
// }

import {
  RawFreelancer,
  ClientSnapshot,
  ScoredFreelancer,
  FREELANCER_SCORING_WEIGHTS,
} from "./browseFreelancers.types";

// ── 1. SKILL MATCH (30%) ─────────────────────────────────────────
function calcSkillMatch(
  freelancerSkills: string[],
  clientRequiredSkills: string[],
): number {
  if (!clientRequiredSkills.length) return 60;
  if (!freelancerSkills.length) return 0;

  const freelancerSet = new Set(freelancerSkills.map((s) => s.toLowerCase()));
  const matched = clientRequiredSkills.filter((s) =>
    freelancerSet.has(s.toLowerCase()),
  ).length;

  return Math.round((matched / clientRequiredSkills.length) * 100);
}

// ── 2. RATING SCORE (25%) ────────────────────────────────────────
function calcRatingScore(
  averageRating?: number | null,
  totalReviews?: number,
): number {
  if (!averageRating) return 40;

  const base = (Math.min(averageRating, 5) / 5) * 90;
  const volumeBonus = Math.min((totalReviews ?? 0) / 20, 1) * 10;

  return Math.round(Math.min(100, base + volumeBonus));
}

// ── 3. AVAILABILITY SCORE (20%) ──────────────────────────────────
function calcAvailabilityScore(
  availability: "AVAILABLE" | "BUSY" | "UNAVAILABLE",
): number {
  switch (availability) {
    case "AVAILABLE":
      return 100;
    case "BUSY":
      return 40;
    case "UNAVAILABLE":
      return 0;
    default:
      return 0;
  }
}

// ── 4. BUDGET FIT SCORE (10%) ────────────────────────────────────
function calcBudgetFit(
  freelancerHourlyRate?: number | null,
  client?: Pick<ClientSnapshot, "hourlyBudgetMin" | "hourlyBudgetMax">,
): number {
  if (!freelancerHourlyRate) return 50;
  if (!client?.hourlyBudgetMin && !client?.hourlyBudgetMax) return 50;

  const min = client.hourlyBudgetMin ?? 0;
  const max = client.hourlyBudgetMax ?? Infinity;

  if (freelancerHourlyRate >= min && freelancerHourlyRate <= max) {
    return 100;
  } else if (freelancerHourlyRate > max) {
    const overage = freelancerHourlyRate - max;
    return Math.max(0, Math.round(100 - (overage / max) * 100));
  } else {
    const underage = min - freelancerHourlyRate;
    return Math.max(0, Math.round(100 - (underage / min) * 100));
  }
}

// ── 5. SUCCESS SCORE (10%) ───────────────────────────────────────
function calcSuccessScore(
  freelancer: Pick<
    RawFreelancer,
    "completedContracts" | "profileCompletionScore"
  >,
): number {
  let score = 30;

  const contractPoints = Math.min(freelancer.completedContracts, 15) * 3;
  score += contractPoints;

  const profilePoints =
    (Math.min(freelancer.profileCompletionScore, 100) / 100) * 35;
  score += profilePoints;

  return Math.round(Math.max(0, Math.min(100, score)));
}

// ── 6. ACTIVITY SCORE (5% - Last Login) ─────────────────────────
function calcActivityScore(lastLoginAt?: Date | null): number {
  if (!lastLoginAt) return 30;

  const daysSinceLogin =
    (Date.now() - new Date(lastLoginAt).getTime()) / 86_400_000;

  return Math.round(Math.max(0, 100 - (daysSinceLogin / 30) * 100));
}

// ── 7. PERSONAL BOOST (multiplier) ──────────────────────────────
function calcPersonalBoost(
  freelancer: RawFreelancer,
  client: ClientSnapshot,
): number {
  let boost = 1.0;

  if (client.viewedFreelancerIds.includes(freelancer.id)) boost -= 0.05;
  if (client.hiredFreelancerIds.includes(freelancer.id)) boost -= 0.15;

  if (
    client.preferredRegion &&
    freelancer.region &&
    client.preferredRegion.toLowerCase() === freelancer.region.toLowerCase()
  ) {
    boost += 0.08;
  }

  if (
    client.preferredExpLevel &&
    freelancer.experienceLevel === client.preferredExpLevel
  ) {
    boost += 0.07;
  }

  const freelancerLangs = (freelancer.languages as any[]) || [];
  const freelancerLangNames = new Set(
    freelancerLangs.map((l: any) => (l.name || l).toLowerCase()),
  );

  if (
    client.preferredLanguage &&
    freelancerLangNames.has(client.preferredLanguage.toLowerCase())
  ) {
    boost += 0.05;
  }

  const commonLangs = client.spokenLanguages.filter((l) =>
    freelancerLangNames.has(l.toLowerCase()),
  );

  if (commonLangs.length > 0) {
    boost += 0.03 * Math.min(commonLangs.length, 2);
  }

  return Math.min(Math.max(boost, 0.5), 1.25);
}

// ── MASTER SCORER ────────────────────────────────────────────────
export function scoreFreelancer(
  freelancer: RawFreelancer,
  client: ClientSnapshot,
): Omit<ScoredFreelancer, keyof RawFreelancer> {
  const freelancerSkillNames = freelancer.skills.map((s) => s.skill.name);

  const skillMatch = calcSkillMatch(
    freelancerSkillNames,
    client.requiredSkills,
  );
  const rating = calcRatingScore(
    freelancer.averageRating,
    freelancer.totalReviews,
  );
  const availability = calcAvailabilityScore(freelancer.availability);
  const budgetFit = calcBudgetFit(freelancer.hourlyRate, client);
  const successScore = calcSuccessScore(freelancer);
  const activityScore = calcActivityScore(freelancer.lastLoginAt);
  const personalBoost = calcPersonalBoost(freelancer, client);

  const weighted =
    skillMatch * FREELANCER_SCORING_WEIGHTS.skillMatch +
    rating * FREELANCER_SCORING_WEIGHTS.rating +
    availability * FREELANCER_SCORING_WEIGHTS.availability +
    budgetFit * FREELANCER_SCORING_WEIGHTS.budgetFit +
    successScore * FREELANCER_SCORING_WEIGHTS.successScore +
    activityScore * FREELANCER_SCORING_WEIGHTS.activityScore;

  const score = Math.round(Math.min(100, weighted * personalBoost));

  return {
    score,
    matchPercentage: skillMatch,
    isExploration: false,
    scoreBreakdown: {
      skillMatch,
      rating,
      availability,
      budgetFit,
      successScore,
      activityScore,
      profileScore: freelancer.profileCompletionScore,
    },
  };
}
