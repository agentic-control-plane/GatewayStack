// packages/transformabl/src/index.ts
//
// Express middleware for content transformation and safety preprocessing.

import type { RequestHandler } from "express";
import {
  transformContent,
  type TransformConfig,
  type TransformResult,
} from "@gatewaystack/transformabl-core";

export interface TransformablMiddlewareConfig extends TransformConfig {
  /**
   * Extract text content from the request to analyze.
   * Default: JSON.stringify(req.body).
   */
  extractContent?: (req: any) => string;
  /**
   * Whether to replace req.body with redacted content.
   * Default: false (attach metadata only, don't modify body).
   */
  redactBody?: boolean;
  /**
   * Risk score threshold to block requests (0-100).
   * Requests with riskScore >= this value are rejected with 403.
   * Default: undefined (don't block, only annotate).
   */
  blockThreshold?: number;
}

/**
 * Express middleware that analyzes and optionally transforms request content.
 *
 * Attaches analysis results to `req.transformabl` for downstream use
 * by validatabl (policy decisions based on content risk) and explicabl (audit logging).
 *
 * Use BEFORE validatabl in the middleware chain so policies can reference
 * content classification results.
 */
export function transformabl(config?: TransformablMiddlewareConfig): RequestHandler {
  return (req: any, res, next) => {
    const content = config?.extractContent
      ? config.extractContent(req)
      : typeof req.body === "string"
        ? req.body
        : JSON.stringify(req.body ?? {});

    const result: TransformResult = transformContent(content, config);

    // Attach to request for downstream middleware
    req.transformabl = result;

    // Block if risk score exceeds threshold
    if (
      config?.blockThreshold !== undefined &&
      result.classification.riskScore >= config.blockThreshold
    ) {
      return res.status(403).json({
        error: "content_blocked",
        message: `Content risk score (${result.classification.riskScore}) exceeds threshold (${config.blockThreshold})`,
        labels: result.classification.labels,
      });
    }

    // Optionally redact the body in-place
    if (config?.redactBody && result.transformed) {
      try {
        req.body = JSON.parse(result.content);
      } catch {
        // If content isn't valid JSON after redaction, set as string
        req.body = result.content;
      }
    }

    return next();
  };
}

// Re-export core for direct access
export {
  transformContent,
  detectPii,
  detectPiiDetailed,
  MAX_PII_SCAN_LENGTH,
  redactPii,
  classifyContent,
  extractMetadata,
} from "@gatewaystack/transformabl-core";

export type {
  TransformConfig,
  TransformResult,
  PiiType,
  PiiMatch,
  RedactionConfig,
  RedactionMode,
  ClassificationLabel,
  ClassificationResult,
  ContentMetadata,
  SafetyCategory,
  RegulatoryCategory,
} from "@gatewaystack/transformabl-core";
