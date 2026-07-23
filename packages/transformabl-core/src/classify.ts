// packages/transformabl-core/src/classify.ts
//
// Content classification: safety risks + regulatory content detection.
//
// FUTURE WORK:
// - ML-based classification for higher accuracy
// - Hate speech / toxic content detection
// - Competitor mention detection (configurable keyword lists)
// - Proprietary information detection
// - Multi-language support
// - Configurable per-tenant classification rules

import type {
  PiiMatch,
  ClassificationLabel,
  ClassificationResult,
  SafetyCategory,
  RegulatoryCategory,
} from "./types.js";

/** Patterns that suggest prompt injection or jailbreak attempts. */
const SAFETY_PATTERNS: Array<{ category: SafetyCategory; patterns: RegExp[] }> = [
  {
    category: "prompt_injection",
    patterns: [
      /ignore\s+(all\s+)?previous\s+instructions/i,
      /disregard\s+(all\s+)?prior\s+(instructions|context)/i,
      /you\s+are\s+now\s+(?:a|an)\s+\w+/i,
      /system\s*:\s*you\s+are/i,
      /\bdo\s+anything\s+now\b/i,
      /\bDAN\s+mode\b/i,
    ],
  },
  {
    category: "jailbreak_attempt",
    patterns: [
      /bypass\s+(?:your\s+)?(?:safety|content|moderation)\s+(?:filters?|guidelines?|restrictions?)/i,
      /pretend\s+(?:you\s+)?(?:have\s+)?no\s+(?:restrictions?|limitations?|rules?)/i,
      /act\s+as\s+(?:if\s+)?(?:you\s+)?(?:have|had)\s+no\s+(?:ethics|morals|guidelines)/i,
    ],
  },
  {
    category: "code_injection",
    patterns: [
      /(?:exec|eval|system)\s*\(/i,
      /__import__\s*\(/i,
      /os\.(?:system|popen|exec)/i,
      /subprocess\.(?:run|call|Popen)/i,
    ],
  },
];

/** Map PII types to regulatory categories. */
const PII_TO_REGULATORY: Record<string, RegulatoryCategory[]> = {
  ssn: ["pci", "gdpr"],
  credit_card: ["pci"],
  email: ["gdpr", "coppa"],
  phone: ["gdpr"],
  date_of_birth: ["gdpr", "coppa", "hipaa"],
  ip_address: ["gdpr"],
  us_bank_number: ["pci", "gdpr"],
  us_itin: ["pci", "gdpr"],
  us_passport: ["gdpr"],
  us_drivers_license: ["gdpr"],
  iban: ["pci", "gdpr"],
  icd_10: ["hipaa"],
  icd_9: ["hipaa"],
  npi: ["hipaa"],
  crypto_wallet: ["gdpr"],
};

/**
 * Classify content for safety risks and regulatory concerns.
 */
export function classifyContent(
  text: string,
  piiMatches: PiiMatch[]
): ClassificationResult {
  const labels: ClassificationLabel[] = [];

  // Safety classification
  for (const { category, patterns } of SAFETY_PATTERNS) {
    for (const pattern of patterns) {
      if (pattern.test(text)) {
        labels.push({
          category,
          confidence: "medium",
          detail: `Matched pattern: ${pattern.source.slice(0, 50)}`,
        });
        break; // One match per category is enough
      }
    }
  }

  // Regulatory classification based on PII found
  const regulatoryCategories = new Set<RegulatoryCategory>();
  for (const match of piiMatches) {
    const categories = PII_TO_REGULATORY[match.type];
    if (categories) {
      for (const cat of categories) regulatoryCategories.add(cat);
    }
  }

  for (const category of regulatoryCategories) {
    const piiTypes = piiMatches
      .filter((m) => PII_TO_REGULATORY[m.type]?.includes(category))
      .map((m) => m.type);
    labels.push({
      category,
      confidence: "high",
      detail: `PII detected: ${[...new Set(piiTypes)].join(", ")}`,
    });
  }

  // Compute risk score
  const hasSafetyRisk = labels.some((l) =>
    ["prompt_injection", "jailbreak_attempt", "code_injection"].includes(l.category)
  );
  const hasRegulatoryContent = regulatoryCategories.size > 0;

  let riskScore = 0;
  if (hasSafetyRisk) riskScore += 50;
  if (hasRegulatoryContent) riskScore += 20;
  riskScore += Math.min(piiMatches.length * 5, 30); // Up to 30 for PII density
  riskScore = Math.min(riskScore, 100);

  return { labels, riskScore, hasSafetyRisk, hasRegulatoryContent };
}
