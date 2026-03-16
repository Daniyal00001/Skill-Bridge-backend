import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  console.log("🌱 Seeding metadata...");

  // Languages
 const languages = [
  { name: "English", code: "en" },
  { name: "Spanish", code: "es" },
  { name: "French", code: "fr" },
  { name: "German", code: "de" },
  { name: "Italian", code: "it" },
  { name: "Portuguese", code: "pt" },
  { name: "Russian", code: "ru" },
  { name: "Mandarin Chinese", code: "zh" },
  { name: "Cantonese", code: "yue" },
  { name: "Japanese", code: "ja" },
  { name: "Korean", code: "ko" },
  { name: "Hindi", code: "hi" },
  { name: "Urdu", code: "ur" },
  { name: "Bengali", code: "bn" },
  { name: "Punjabi", code: "pa" },
  { name: "Turkish", code: "tr" },
  { name: "Arabic", code: "ar" },
  { name: "Persian", code: "fa" },
  { name: "Hebrew", code: "he" },
  { name: "Indonesian", code: "id" },
  { name: "Malay", code: "ms" },
  { name: "Thai", code: "th" },
  { name: "Vietnamese", code: "vi" },
  { name: "Filipino", code: "tl" },
  { name: "Polish", code: "pl" },
  { name: "Dutch", code: "nl" },
  { name: "Swedish", code: "sv" },
  { name: "Norwegian", code: "no" },
  { name: "Danish", code: "da" },
  { name: "Finnish", code: "fi" },
  { name: "Greek", code: "el" },
  { name: "Czech", code: "cs" },
  { name: "Hungarian", code: "hu" },
  { name: "Romanian", code: "ro" },
  { name: "Ukrainian", code: "uk" },
  { name: "Swahili", code: "sw" },
  { name: "Afrikaans", code: "af" },
];

  for (const lang of languages) {
    await prisma.language.upsert({
      where: { name: lang.name },
      update: {},
      create: lang,
    });
  }

  // Locations
const locations = [
  { name: "Any location", region: "Global" },

  { name: "North America", region: "Americas" },
  { name: "South America", region: "Americas" },
  { name: "Central America", region: "Americas" },
  { name: "Caribbean", region: "Americas" },

  { name: "Western Europe", region: "Europe" },
  { name: "Eastern Europe", region: "Europe" },
  { name: "Northern Europe", region: "Europe" },
  { name: "Southern Europe", region: "Europe" },

  { name: "South Asia", region: "Asia" },
  { name: "Southeast Asia", region: "Asia" },
  { name: "East Asia", region: "Asia" },
  { name: "Central Asia", region: "Asia" },

  { name: "Middle East", region: "Middle East" },

  { name: "North Africa", region: "Africa" },
  { name: "West Africa", region: "Africa" },
  { name: "East Africa", region: "Africa" },
  { name: "Southern Africa", region: "Africa" },

  { name: "Australia & New Zealand", region: "Oceania" },
  { name: "Pacific Islands", region: "Oceania" },
];

  for (const loc of locations) {
    await prisma.location.upsert({
      where: { name: loc.name },
      update: {},
      create: loc,
    });
  }

  console.log("✅ Metadata seeding completed.");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
