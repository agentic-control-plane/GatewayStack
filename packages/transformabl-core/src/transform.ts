// packages/transformabl-core/src/transform.ts
//
// Full transformation pipeline: detect → classify → redact → extract metadata.

import type { TransformConfig, TransformResult } from "./types.js";
import { detectPiiDetailed } from "./detect.js";
import { redactPii } from "./redact.js";
import { classifyContent } from "./classify.js";
import { extractMetadata } from "./metadata.js";

/**
 * Run the full transformation pipeline on content.
 *
 * 1. Detect PII
 * 2. Classify content (safety + regulatory)
 * 3. Redact PII
 * 4. Extract metadata
 *
 * Returns both the transformed content and all analysis results.
 */
export function transformContent(
  content: string,
  config?: TransformConfig
): TransformResult {
  // 1. Detect PII
  const detection = detectPiiDetailed(content, config?.customPatterns);
  const piiMatches = detection.matches;

  // 2. Classify
  const classification =
    config?.classify !== false
      ? classifyContent(content, piiMatches)
      : { labels: [], riskScore: 0, hasSafetyRisk: false, hasRegulatoryContent: false };

  // 3. Redact
  const redacted = piiMatches.length > 0
    ? redactPii(content, piiMatches, config?.redaction)
    : content;

  // 4. Metadata
  const metadata =
    config?.extractMetadata !== false
      ? extractMetadata(content, piiMatches, classification)
      : {
          contentLength: content.length,
          piiTypesDetected: [],
          piiMatchCount: 0,
          riskScore: 0,
          labels: [],
        };

  return {
    content: redacted,
    piiMatches,
    classification,
    metadata,
    transformed: redacted !== content,
    scanTruncated: detection.scanTruncated,
  };
}
