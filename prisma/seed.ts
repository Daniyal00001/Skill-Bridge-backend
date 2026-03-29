// prisma/seed.ts
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

const CATEGORIES = [
  {
    name: "Web Development",
    slug: "web-development",
    icon: "Layout",
    subs: [
      "Frontend Development",
      "Backend Development",
      "Full Stack Development",
      "E-commerce Development",
      "WordPress & CMS",
      "Web Scraping",
      "REST API Development",
      "GraphQL Development",
      "Progressive Web Apps",
      "Landing Pages",
    ],
  },
  {
    name: "Mobile Development",
    slug: "mobile-development",
    icon: "Smartphone",
    subs: [
      "iOS Development",
      "Android Development",
      "React Native",
      "Flutter",
      "Xamarin",
      "Mobile UI/UX",
      "App Store Optimization",
      "Mobile Game Development",
      "Wearable App Development",
      "Mobile Backend (BaaS)",
    ],
  },
  {
    name: "UI/UX Design",
    slug: "ui-ux-design",
    icon: "Figma",
    subs: [
      "Web Design",
      "Mobile App Design",
      "UI Design",
      "UX Research",
      "Wireframing & Prototyping",
      "Design Systems",
      "Landing Page Design",
      "Dashboard Design",
      "SaaS Product Design",
      "Usability Testing",
    ],
  },
  {
    name: "Graphic Design",
    slug: "graphic-design",
    icon: "Brush",
    subs: [
      "Logo Design",
      "Brand Identity",
      "Print Design",
      "Illustration",
      "Packaging Design",
      "Infographic Design",
      "Social Media Graphics",
      "Presentation Design",
      "T-shirt & Merchandise",
      "Icon Design",
    ],
  },
  {
    name: "AI & Machine Learning",
    slug: "ai-machine-learning",
    icon: "Sparkles",
    subs: [
      "Machine Learning Models",
      "Deep Learning",
      "Natural Language Processing",
      "Computer Vision",
      "Data Annotation & Labeling",
      "LLM Integration",
      "AI Chatbots",
      "Recommendation Systems",
      "Predictive Analytics",
      "MLOps & Deployment",
    ],
  },
  {
    name: "Data Science & Analytics",
    slug: "data-science",
    icon: "BarChart2",
    subs: [
      "Data Analysis",
      "Data Visualization",
      "Business Intelligence",
      "Statistical Modeling",
      "ETL Pipeline Development",
      "Big Data (Spark/Hadoop)",
      "SQL & Database Querying",
      "A/B Testing & Experimentation",
      "Financial Modeling",
      "Google Analytics & Reporting",
    ],
  },
  {
    name: "DevOps & Cloud",
    slug: "devops-cloud",
    icon: "Cloud",
    subs: [
      "AWS",
      "Google Cloud Platform",
      "Microsoft Azure",
      "Docker & Kubernetes",
      "CI/CD Pipelines",
      "Infrastructure as Code",
      "Linux Server Administration",
      "Site Reliability Engineering",
      "Database Administration",
      "Cloud Security",
    ],
  },
  {
    name: "Cybersecurity",
    slug: "cybersecurity",
    icon: "Shield",
    subs: [
      "Penetration Testing",
      "Vulnerability Assessment",
      "Security Audits",
      "Network Security",
      "Application Security",
      "Blockchain Security",
      "Incident Response",
      "Security Consulting",
      "GDPR & Compliance",
      "Malware Analysis",
    ],
  },
  {
    name: "Blockchain & Web3",
    slug: "blockchain-web3",
    icon: "Link",
    subs: [
      "Smart Contract Development",
      "Solidity",
      "DeFi Development",
      "NFT Development",
      "Web3 Frontend (ethers.js)",
      "Tokenomics Design",
      "Blockchain Consulting",
      "DAO Development",
      "Crypto Wallet Integration",
      "Layer 2 Solutions",
    ],
  },
  {
    name: "Game Development",
    slug: "game-development",
    icon: "Gamepad2",
    subs: [
      "Unity Development",
      "Unreal Engine",
      "2D Game Development",
      "3D Game Development",
      "Mobile Game Development",
      "Game UI/UX",
      "Multiplayer & Networking",
      "Game Art & Assets",
      "VR/AR Games",
      "Game Design & Mechanics",
    ],
  },
  {
    name: "Software Development",
    slug: "software-development",
    icon: "Code2",
    subs: [
      "Desktop Applications",
      "SaaS Development",
      "Microservices Architecture",
      "API Integrations",
      "Browser Extensions",
      "Automation & Scripting",
      "Legacy System Migration",
      "Software Testing & QA",
      "SDK Development",
      "Plugin Development",
    ],
  },
  {
    name: "Embedded & IoT",
    slug: "embedded-iot",
    icon: "Cpu",
    subs: [
      "Arduino & Raspberry Pi",
      "Embedded C/C++",
      "Firmware Development",
      "IoT Platform Integration",
      "PCB Design",
      "RTOS Development",
      "Industrial Automation",
      "Home Automation",
      "Drone & Robotics",
      "Sensor & Data Acquisition",
    ],
  },
  {
    name: "Writing & Content",
    slug: "writing-content",
    icon: "PenLine",
    subs: [
      "Blog & Article Writing",
      "Copywriting",
      "Technical Writing",
      "SEO Writing",
      "Ghost Writing",
      "UX Writing",
      "Resume & Cover Letters",
      "Proofreading & Editing",
      "Academic Writing",
      "Script & Screenplay Writing",
    ],
  },
  {
    name: "Digital Marketing",
    slug: "digital-marketing",
    icon: "Megaphone",
    subs: [
      "SEO",
      "Social Media Marketing",
      "PPC & Google Ads",
      "Email Marketing",
      "Content Marketing",
      "Influencer Marketing",
      "Conversion Rate Optimization",
      "Marketing Automation",
      "Affiliate Marketing",
      "Brand Strategy",
    ],
  },
  {
    name: "Video & Animation",
    slug: "video-animation",
    icon: "Video",
    subs: [
      "Video Editing",
      "Motion Graphics",
      "2D Animation",
      "3D Animation",
      "Explainer Videos",
      "YouTube Production",
      "Video Ads",
      "VFX & Compositing",
      "Whiteboard Animation",
      "Podcast Editing",
    ],
  },
  {
    name: "Audio & Music",
    slug: "audio-music",
    icon: "Music",
    subs: [
      "Music Production",
      "Sound Design",
      "Voice Over",
      "Audio Editing & Mixing",
      "Mastering",
      "Jingle & Soundtrack",
      "Podcast Production",
      "Audio Branding",
      "Song Writing",
      "Transcription",
    ],
  },
  {
    name: "3D & AR/VR",
    slug: "3d-ar-vr",
    icon: "Box",
    subs: [
      "3D Modeling",
      "3D Rendering & Visualization",
      "Product Visualization",
      "Architectural Visualization",
      "AR Development",
      "VR Development",
      "3D Animation",
      "Character Design",
      "Environment Design",
      "3D Printing Models",
    ],
  },
  {
    name: "Business & Consulting",
    slug: "business-consulting",
    icon: "Briefcase",
    subs: [
      "Business Planning",
      "Market Research",
      "Financial Consulting",
      "Legal Consulting",
      "HR & Recruiting",
      "Project Management",
      "Operations Consulting",
      "Startup Consulting",
      "Product Strategy",
      "Pitch Deck Creation",
    ],
  },
  {
    name: "Translation & Languages",
    slug: "translation-languages",
    icon: "Languages",
    subs: [
      "Document Translation",
      "Website Localization",
      "Legal Translation",
      "Technical Translation",
      "Subtitling & Captioning",
      "Interpretation",
      "Transcription",
      "Language Tutoring",
      "Cultural Consulting",
      "App Localization",
    ],
  },
  {
    name: "Admin & Virtual Assistance",
    slug: "admin-virtual-assistance",
    icon: "ClipboardList",
    subs: [
      "Virtual Assistant",
      "Data Entry",
      "Customer Support",
      "Email Management",
      "Scheduling & Calendar",
      "Research & Sourcing",
      "CRM Management",
      "E-commerce Support",
      "Social Media Management",
      "Lead Generation",
    ],
  },

  {
    name: "AI Content Creation",
    slug: "ai-content-creation",
    icon: "Bot",
    subs: [
      "AI Blog Writing",
      "AI Image Generation",
      "Prompt Engineering",
      "ChatGPT Integration",
      "AI Marketing Content",
      "AI Script Writing",
      "AI SEO Content",
      "AI Video Generation",
      "AI Voice Generation",
      "AI Workflow Automation",
    ],
  },
  {
    name: "Legal Services",
    slug: "legal-services",
    icon: "Scale",
    subs: [
      "Contract Drafting",
      "Legal Consulting",
      "Trademark Registration",
      "Intellectual Property",
      "Privacy Policy Writing",
      "Terms & Conditions",
      "Startup Legal Consulting",
      "Employment Law",
      "Compliance Consulting",
      "Legal Research",
    ],
  },
  {
    name: "Architecture & Interior Design",
    slug: "architecture-interior-design",
    icon: "Building2",
    subs: [
      "Architectural Design",
      "Interior Design",
      "Floor Plan Design",
      "3D Architectural Rendering",
      "Landscape Design",
      "Urban Planning",
      "Lighting Design",
      "Furniture Design",
      "CAD Drafting",
      "Building Information Modeling",
    ],
  },
  {
    name: "Quality Assurance & Testing",
    slug: "quality-assurance-testing",
    icon: "CheckCircle",
    subs: [
      "Manual Testing",
      "Automation Testing",
      "Selenium Testing",
      "Cypress Testing",
      "Playwright Testing",
      "API Testing",
      "Performance Testing",
      "Load Testing",
      "Mobile App Testing",
      "Security Testing",
    ],
  },
];

// ✅ Export as a function so index.ts can call it
export async function seedCategories() {
  console.log("🌱 Seeding categories and subcategories...\n");

  let categoryCount = 0;
  let subCategoryCount = 0;

  for (const cat of CATEGORIES) {
    const created = await prisma.category.upsert({
      where: { slug: cat.slug },
      update: { name: cat.name, icon: cat.icon },
      create: { name: cat.name, slug: cat.slug, icon: cat.icon },
    });

    categoryCount++;
    console.log(`✅ Category: ${created.name}`);

    for (const subName of cat.subs) {
      const subSlug = subName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "");

      await prisma.subCategory.upsert({
        where: { categoryId_slug: { categoryId: created.id, slug: subSlug } },
        update: { name: subName },
        create: { name: subName, slug: subSlug, categoryId: created.id },
      });

      subCategoryCount++;
      console.log(`   └─ ${subName}`);
    }
  }

  console.log("\n────────────────────────────────────");
  console.log(`🎉 Seeded ${categoryCount} categories`);
  console.log(`🎉 Seeded ${subCategoryCount} subcategories`);
  console.log("────────────────────────────────────");
}

// ✅ Keep this so you can still run seed.ts standalone
async function main() {
  await seedCategories();
}

if (require.main === module) {
  main()
    .catch((e) => {
      console.error("❌ Seed failed:", e);
      process.exit(1);
    })
    .finally(async () => {
      await prisma.$disconnect();
    });
}

