// packages/transformabl-core/src/types.ts

/** Categories of PII that can be detected. */
export type PiiType =
  // Universal
  | "email"
  | "phone"
  | "ssn"
  | "credit_card"
  | "ip_address"
  | "date_of_birth"
  // US identifiers (Presidio parity)
  | "us_bank_number"
  | "us_itin"
  | "us_passport"
  | "us_drivers_license"
  // International banking
  | "iban"
  // Healthcare (HIPAA PHI)
  | "icd_10"
  | "icd_9"
  | "npi"
  // Financial
  | "crypto_wallet";

/** A single PII detection match. */
export interface PiiMatch {
  type: PiiType;
  value: string;
  start: number;
  end: number;
}

/** How to handle detected PII. */
export type RedactionMode = "mask" | "remove" | "placeholder";

/** Configuration for PII redaction. */
export interface RedactionConfig {
  /** Which PII types to redact. Default: all detected types. */
  types?: PiiType[];
  /** How to redact. Default: "mask". */
  mode?: RedactionMode;
  /** Custom placeholder format. Default: "[{TYPE}]" (e.g., "[EMAIL]"). */
  placeholder?: string;
  /** Mask character. Default: "*". */
  maskChar?: string;
  /** Number of characters to keep visible at start/end when masking. Default: 2. */
  maskKeep?: number;
}

/** Safety risk categories. */
export type SafetyCategory =
  | "prompt_injection"
  | "jailbreak_attempt"
  | "code_injection";

/** Regulatory compliance categories. */
export type RegulatoryCategory =
  | "hipaa"
  | "pci"
  | "gdpr"
  | "coppa";

/** A content classification label. */
export interface ClassificationLabel {
  category: SafetyCategory | RegulatoryCategory | string;
  confidence: "high" | "medium" | "low";
  detail?: string;
}

/** Result of content classification. */
export interface ClassificationResult {
  labels: ClassificationLabel[];
  riskScore: number; // 0-100
  hasSafetyRisk: boolean;
  hasRegulatoryContent: boolean;
}

/** Metadata extracted from content. */
export interface ContentMetadata {
  /** Length of the original content. */
  contentLength: number;
  /** PII types detected (if any). */
  piiTypesDetected: PiiType[];
  /** Number of PII matches found. */
  piiMatchCount: number;
  /** Risk score (0-100). */
  riskScore: number;
  /** Classification labels. */
  labels: ClassificationLabel[];
}

/** Full transformation result. */
export interface TransformResult {
  /** The transformed content (with PII redacted). */
  content: string;
  /** PII matches found in the original content. */
  piiMatches: PiiMatch[];
  /** Classification result. */
  classification: ClassificationResult;
  /** Extracted metadata. */
  metadata: ContentMetadata;
  /** Whether any transformation was applied. */
  transformed: boolean;
}

/** Configuration for the full transformation pipeline. */
export interface TransformConfig {
  /** PII detection and redaction settings. */
  redaction?: RedactionConfig;
  /** Enable content classification. Default: true. */
  classify?: boolean;
  /** Enable metadata extraction. Default: true. */
  extractMetadata?: boolean;
  /** Custom PII patterns to add to the built-in set. */
  customPatterns?: Array<{ type: string; pattern: RegExp }>;
}
