/**
 * Content Shield — PII redaction for message text sent to the model.
 *
 * Pure-TypeScript port of the regex mode of privacy-filter.py (agentive-work),
 * so the bundled plugin stays zero-dependency: the 15 patterns run inline with
 * no engine call. The ML (ONNX) mode is intentionally not ported; it remains a
 * roadmap item in the Python script.
 *
 * Faithful-port note: the DOB and IPv4 patterns are aggressive by design
 * (they will redact ordinary dates and addresses in user text). The upstream
 * script accepted this trade-off for user-typed content and so do we. Set
 * AGENTFILTER_DISABLE_CONTENT_SHIELD=1 to opt out entirely.
 */

export interface Finding {
  type: string
  label: string
  value: string
}

export interface TextPart {
  type: string
  text?: string
}

/** [name, pattern, replacement]. Invariant: replacement contains no "$". */
export const CONTENT_PATTERNS: Array<[string, RegExp, string]> = [
  ["credit_card", /\b(?:\d{4}[-\s]?){3}\d{4}\b/gi, "[CREDIT_CARD]"],
  ["cvv", /\bcvv\s*[:=]?\s*\d{3,4}\b/gi, "[CVV]"],
  ["cvc", /\bcvc\s*[:=]?\s*\d{3,4}\b/gi, "[CVC]"],
  ["ssn", /\b\d{3}-\d{2}-\d{4}\b/gi, "[SSN]"],
  ["email", /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/gi, "[EMAIL]"],
  ["phone_us", /\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/gi, "[PHONE]"],
  ["phone_cn", /\b1[3-9]\d[-.\s]?\d{4}[-.\s]?\d{4}\b/gi, "[PHONE]"],
  ["ipv4", /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/gi, "[IP_ADDR]"],
  ["dob", /\b\d{2,4}[/-]\d{1,2}[/-]\d{2,4}\b/gi, "[DOB]"],
  ["api_key", /\bsk[-_][a-zA-Z0-9][-_a-zA-Z0-9]{20,}\b/gi, "[API_KEY]"],
  ["aws_key", /\bAKIA[0-9A-Z]{16}\b/gi, "[AWS_KEY]"],
  ["github_pat", /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/gi, "[GITHUB_TOKEN]"],
  ["password", /\bpassword\s*[:=]\s*\S+\b/gi, "[PASSWORD]"],
  ["jwt", /\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/gi, "[JWT]"],
  ["private_key", /-----BEGIN\s+(?:(?:RSA|EC|DSA|OPENSSH)\s+)?PRIVATE\s+KEY-----/gi, "[PRIVATE_KEY]"],
]

const fresh = (pattern: RegExp): RegExp => new RegExp(pattern.source, pattern.flags)

export const redactText = (text: string): { redacted: string; findings: Finding[] } => {
  let redacted = text
  const findings: Finding[] = []
  for (const [name, pattern, replacement] of CONTENT_PATTERNS) {
    // Fresh RegExp per use: /g literals carry lastIndex across calls.
    const matches = redacted.match(fresh(pattern))
    if (!matches) continue
    for (const value of matches) {
      findings.push({ type: name, label: replacement.replace(/[[\]]/g, ""), value })
    }
    redacted = redacted.replace(fresh(pattern), replacement.replace(/\$/g, "$$$$"))
  }
  return { redacted, findings }
}

/**
 * Scrub text parts in place (same mutation semantics as the retired
 * privacy-filter plugin). Returns the number of redacted items.
 */
export const scrubTextParts = (parts?: TextPart[]): number => {
  const targets = (parts ?? []).filter(
    (p) => p?.type === "text" && typeof p.text === "string" && p.text.length > 0,
  )
  let count = 0
  for (const part of targets) {
    const { redacted, findings } = redactText(part.text as string)
    if (findings.length > 0) {
      part.text = redacted
      count += findings.length
    }
  }
  return count
}
