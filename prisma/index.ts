// prisma/index.ts
import { PrismaClient } from "@prisma/client";
import { seedCategories } from "./seed";
import { seedFreelancers } from "./seedFreelancers";
import { seedClients } from "./seedClients";
import { seedMetadata } from "./seed_metadata";

const prisma = new PrismaClient();

async function main() {
  console.log("🚀 Starting full database seed...\n");

  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("📂 Step 0: Seeding Metadata...");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  await seedMetadata();

  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("📂 Step 1: Seeding Categories...");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  await seedCategories();

  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("👥 Step 2: Seeding Freelancers...");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  await seedFreelancers();

  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("💼 Step 3: Seeding Clients...");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  await seedClients();

  console.log("\n🎉 Full seed completed successfully!");
}

main()
  .catch((e) => {
    console.error("❌ Master seed failed:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });