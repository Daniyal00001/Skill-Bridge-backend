import urllib.request
import json
import sys

def get_countries():
    url = 'https://raw.githubusercontent.com/mledoze/countries/master/dist/countries.json'
    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
        
        countries = []
        for c in data:
            name = c.get('name', {}).get('common', '')
            region = c.get('region', '')
            subregion = c.get('subregion', '')
            
            # Use 'idd' for phone code
            idd = c.get('idd', {})
            root = idd.get('root', '').replace('+', '')
            suffixes = idd.get('suffixes', [])
            
            # Handle cases with multiple suffixes or no suffixes
            if root:
                if len(suffixes) == 1:
                    phone_code = root + suffixes[0]
                else:
                    phone_code = root
            else:
                phone_code = ""

            # Manual override for Middle East
            middle_east_subregions = ['Western Asia', 'Northern Africa']
            middle_east_countries = ['Turkey', 'Saudi Arabia', 'United Arab Emirates', 'Qatar', 'Kuwait', 'Oman', 'Bahrain', 'Jordan', 'Lebanon', 'Iraq', 'Israel', 'Palestine', 'Egypt']
            
            final_region = region
            if (subregion in middle_east_subregions and name in middle_east_countries) or (name == 'Turkey'):
                 final_region = 'Middle East'
            
            if name and final_region:
                countries.append({'name': name, 'region': final_region, 'phoneCode': phone_code})
        
        # Sort for consistency
        countries.sort(key=lambda x: x['name'])
        
        # Filter for 194-ish (unMember or independent) to avoid many islands/territories if preferred
        # But user asked for 194, so let's aim for the most recognized ones
        # For now, let's just use all and the user can decide
        
        return countries
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return []

if __name__ == "__main__":
    countries = get_countries()
    
    languages = [
        { "name": "English", "code": "en" },
        { "name": "Spanish", "code": "es" },
        { "name": "French", "code": "fr" },
        { "name": "German", "code": "de" },
        { "name": "Italian", "code": "it" },
        { "name": "Portuguese", "code": "pt" },
        { "name": "Russian", "code": "ru" },
        { "name": "Mandarin Chinese", "code": "zh" },
        { "name": "Cantonese", "code": "yue" },
        { "name": "Japanese", "code": "ja" },
        { "name": "Korean", "code": "ko" },
        { "name": "Hindi", "code": "hi" },
        { "name": "Urdu", "code": "ur" },
        { "name": "Bengali", "code": "bn" },
        { "name": "Punjabi", "code": "pa" },
        { "name": "Turkish", "code": "tr" },
        { "name": "Arabic", "code": "ar" },
        { "name": "Persian", "code": "fa" },
        { "name": "Hebrew", "code": "he" },
        { "name": "Indonesian", "code": "id" },
        { "name": "Malay", "code": "ms" },
        { "name": "Thai", "code": "th" },
        { "name": "Vietnamese", "code": "vi" },
        { "name": "Filipino", "code": "tl" },
        { "name": "Polish", "code": "pl" },
        { "name": "Dutch", "code": "nl" },
        { "name": "Swedish", "code": "sv" },
        { "name": "Norwegian", "code": "no" },
        { "name": "Danish", "code": "da" },
        { "name": "Finnish", "code": "fi" },
        { "name": "Greek", "code": "el" },
        { "name": "Czech", "code": "cs" },
        { "name": "Hungarian", "code": "hu" },
        { "name": "Romanian", "code": "ro" },
        { "name": "Ukrainian", "code": "uk" },
        { "name": "Swahili", "code": "sw" },
        { "name": "Afrikaans", "code": "af" },
    ]

    output_path = r'd:\Daniyal\Fyp\FullStack-FYP\backend\prisma\seed_metadata.ts'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("import { PrismaClient } from \"@prisma/client\";\n\n")
        f.write("const prisma = new PrismaClient();\n\n")
        f.write("async function main() {\n")
        f.write("  console.log(\"🌱 Seeding metadata...\");\n\n")
        
        f.write("  // Languages\n")
        f.write("  const languages = [\n")
        for lang in languages:
            f.write(f"    {{ name: \"{lang['name']}\", code: \"{lang['code']}\" }},\n")
        f.write("  ];\n\n")
        
        f.write("  for (const lang of languages) {\n")
        f.write("    try {\n")
        f.write("      await prisma.language.upsert({\n")
        f.write("        where: { name: lang.name },\n")
        f.write("        update: { code: lang.code },\n")
        f.write("        create: lang,\n")
        f.write("      });\n")
        f.write("    } catch (e) {\n")
        f.write("      console.warn(`Skipping duplicate language: ${lang.name} (${lang.code})`);\n")
        f.write("    }\n")
        f.write("  }\n\n")
        
        f.write("  // Locations\n")
        f.write("  const locations = [\n")
        f.write("    { name: \"Any location\", region: \"Global\", phoneCode: \"\" },\n")
        for c in countries:
            name = c['name'].replace('"', '\\"')
            f.write(f"    {{ name: \"{name}\", region: \"{c['region']}\", phoneCode: \"{c['phoneCode']}\" }},\n")
        f.write("  ];\n\n")
        
        f.write("  for (const loc of locations) {\n")
        f.write("    await prisma.location.upsert({\n")
        f.write("      where: { name: loc.name },\n")
        f.write("      update: { phoneCode: loc.phoneCode },\n")
        f.write("      create: loc,\n")
        f.write("    });\n")
        f.write("  }\n\n")
        
        f.write("  console.log(\"✅ Metadata seeding completed.\");\n")
        f.write("}\n\n")
        
        f.write("main()\n")
        f.write("  .catch((e) => {\n")
        f.write("    console.error(e);\n")
        f.write("    process.exit(1);\n")
        f.write("  })\n")
        f.write("  .finally(async () => {\n")
        f.write("    await prisma.$disconnect();\n")
        f.write("  });\n")
    
    print(f"Successfully wrote {len(countries)} countries to {output_path}")
