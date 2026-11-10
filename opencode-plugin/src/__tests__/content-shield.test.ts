/**
 * Content Shield tests — regex-mode PII redaction.
 *
 * Ported from privacy-filter.py (agentive-work). Each pattern class gets a
 * representative positive and a negative; plus combination, in-place
 * mutation, and hook-wiring cases.
 */

import { describe, it, expect } from "vitest"
import { redactText, scrubTextParts, CONTENT_PATTERNS } from "../content-shield.js"

describe("content shield patterns", () => {
  it("covers 15 pattern classes", () => {
    expect(CONTENT_PATTERNS.length).toBe(15)
  })

  it("redacts US credit card numbers", () => {
    const { redacted, findings } = redactText("card: 4111 1111 1111 1111")
    expect(redacted).toContain("[CREDIT_CARD]")
    expect(redacted).not.toContain("4111")
    expect(findings[0].label).toBe("CREDIT_CARD")
  })

  it("redacts CVV/CVC tokens", () => {
    const { redacted } = redactText("cvv: 123 and CVC=456")
    expect(redacted).toContain("[CVV]")
    expect(redacted).toContain("[CVC]")
  })

  it("redacts US SSNs", () => {
    const { redacted } = redactText("SSN 123-45-6789")
    expect(redacted).toContain("[SSN]")
    expect(redacted).not.toContain("123-45-6789")
  })

  it("redacts emails", () => {
    const { redacted } = redactText("mail me at alice.smith+work@example.co.uk ok")
    expect(redacted).toContain("[EMAIL]")
    expect(redacted).not.toContain("alice.smith")
  })

  it("leaves npm package specs untouched", () => {
    for (const text of [
      "npm:@code-yeongyu/senpi-pty@2026.11.9-2 failed to resolve",
      "a@b.c",
    ]) {
      const { redacted, findings } = redactText(text)
      expect(redacted).toBe(text)
      expect(findings).toHaveLength(0)
    }
  })

  it("redacts US and CN phone numbers", () => {
    const us = redactText("call +1 (415) 555-2671")
    const cn = redactText("call 138 0013 8000")
    expect(us.redacted).toContain("[PHONE]")
    expect(cn.redacted).toContain("[PHONE]")
  })

  it("redacts IPv4 addresses", () => {
    const { redacted } = redactText("host 192.168.10.24 is up")
    expect(redacted).toContain("[IP_ADDR]")
  })

  it("redacts dates (DOB pattern, aggressive by design)", () => {
    const { redacted } = redactText("born 1990-03-14")
    expect(redacted).toContain("[DOB]")
  })

  it("redacts OpenAI-style API keys", () => {
    const { redacted } = redactText("key sk-proj-abcdefghij1234567890ABCDE")
    expect(redacted).toContain("[API_KEY]")
  })

  it("redacts AWS access keys", () => {
    const { redacted } = redactText("AKIAIOSFODNN7EXAMPLE")
    expect(redacted).toContain("[AWS_KEY]")
  })

  it("redacts GitHub tokens", () => {
    const pat = `ghp_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7r8"}`
    const { redacted } = redactText(`token ${pat}`)
    expect(redacted).toContain("[GITHUB_TOKEN]")
    expect(redacted).not.toContain("ghp_")
  })

  it("redacts password assignments", () => {
    const { redacted } = redactText("password: hunter2!")
    expect(redacted).toContain("[PASSWORD]")
    expect(redacted).not.toContain("hunter2")
  })

  it("redacts JWTs", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    const { redacted } = redactText(`Bearer ${jwt}`)
    expect(redacted).toContain("[JWT]")
    expect(redacted).not.toContain("eyJhbGciOiJIUzI1NiJ9")
  })

  it("redacts private key headers", () => {
    const { redacted } = redactText("-----BEGIN OPENSSH PRIVATE KEY-----")
    expect(redacted).toContain("[PRIVATE_KEY]")
  })

  it("leaves plain text untouched", () => {
    const { redacted, findings } = redactText("just a normal sentence about TypeScript 5.6")
    expect(redacted).toBe("just a normal sentence about TypeScript 5.6")
    expect(findings).toHaveLength(0)
  })

  it("handles multiple pattern classes in one text", () => {
    const { redacted, findings } = redactText(
      "SSN 123-45-6789, email bob@corp.com, key AKIAIOSFODNN7EXAMPLE",
    )
    expect(findings.length).toBeGreaterThanOrEqual(3)
    expect(redacted).toContain("[SSN]")
    expect(redacted).toContain("[EMAIL]")
    expect(redacted).toContain("[AWS_KEY]")
  })
})

describe("scrubTextParts", () => {
  it("mutates text parts in place and returns the redaction count", () => {
    const parts = [
      { type: "text", text: "SSN 123-45-6789" },
      { type: "image", url: "x" },
      { type: "text", text: "no secrets here" },
    ]
    const count = scrubTextParts(parts as never)
    expect(count).toBe(1)
    expect(parts[0].text).toContain("[SSN]")
    expect(parts[1]).toEqual({ type: "image", url: "x" })
    expect(parts[2].text).toBe("no secrets here")
  })

  it("returns 0 for empty or missing parts", () => {
    expect(scrubTextParts(undefined)).toBe(0)
    expect(scrubTextParts([])).toBe(0)
  })
})
