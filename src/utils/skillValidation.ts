export const validateSkillName = (name: string): { valid: boolean; message?: string } => {
  const trimmed = name.trim();

  // 1. Length Check
  if (trimmed.length < 2 || trimmed.length > 30) {
    return { valid: false, message: "Skill must be between 2 and 30 characters." };
  }

  // 2. Valid Characters Regex Check
  const validSkillRegex = /^[a-zA-Z0-9+#.\s-]+$/;
  if (!validSkillRegex.test(trimmed)) {
    return { valid: false, message: "Invalid characters in skill name." };
  }

  // 3. Prevent Spam (e.g. repeated characters more than 3 times in a row)
  const spamRegex = /(.)\1{3,}/;
  if (spamRegex.test(trimmed)) {
    return { valid: false, message: "Skill name contains invalid repeated characters." };
  }

  // 4. Bad Words Filter
  const badWords = [
    "fuck", "shit", "bitch", "ass", "cunt", "nigger", "faggot", "dick", "pussy", "whore", "slut", // standard explicit terms 
    "spam", "fake", "test", "bot"
  ];
  
  const lowerName = trimmed.toLowerCase();
  for (const word of badWords) {
    if (lowerName.includes(word)) {
      return { valid: false, message: "Skill name contains inappropriate language." };
    }
  }

  return { valid: true };
};
