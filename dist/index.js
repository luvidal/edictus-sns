'use strict';

var crypto = require('crypto');

// src/index.ts
var certCache = /* @__PURE__ */ new Map();
var CERT_CACHE_TTL = 60 * 60 * 1e3;
var VALID_CERT_URL_PATTERNS = [
  /^https:\/\/sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?\/SimpleNotificationService-[a-f0-9]+\.pem$/
];
function isValidCertUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") {
      console.error("SNS cert URL not HTTPS:", url);
      return false;
    }
    if (!parsed.hostname.endsWith(".amazonaws.com") && !parsed.hostname.endsWith(".amazonaws.com.cn")) {
      console.error("SNS cert URL not from AWS:", url);
      return false;
    }
    const matches = VALID_CERT_URL_PATTERNS.some((pattern) => pattern.test(url));
    if (!matches) {
      console.error("SNS cert URL does not match expected pattern:", url);
      return false;
    }
    return true;
  } catch {
    console.error("Invalid SNS cert URL:", url);
    return false;
  }
}
async function getCertificate(url, userAgent) {
  const cached = certCache.get(url);
  if (cached && cached.expires > Date.now()) {
    return cached.cert;
  }
  if (!isValidCertUrl(url)) {
    throw new Error("Invalid certificate URL");
  }
  const response = await fetch(url, {
    headers: { "User-Agent": userAgent ?? "avd-sns-verify/1.0" }
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch certificate: ${response.status}`);
  }
  const cert = await response.text();
  if (!cert.includes("-----BEGIN CERTIFICATE-----")) {
    throw new Error("Invalid certificate format");
  }
  try {
    const x509 = new crypto.X509Certificate(cert);
    const issuer = x509.issuer;
    if (!issuer.includes("Amazon") && !issuer.includes("AWS")) {
      console.error("Certificate not issued by Amazon:", issuer);
      throw new Error("Certificate not issued by Amazon");
    }
    const validTo = new Date(x509.validTo);
    if (validTo < /* @__PURE__ */ new Date()) {
      throw new Error("Certificate has expired");
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes("Amazon")) {
      throw err;
    }
    console.error("Certificate validation error:", err);
    throw new Error("Invalid certificate");
  }
  certCache.set(url, {
    cert,
    expires: Date.now() + CERT_CACHE_TTL
  });
  return cert;
}
function buildStringToSign(message) {
  const fields = [];
  if (message.Type === "Notification") {
    fields.push("Message", message.Message);
    fields.push("MessageId", message.MessageId);
    if (message.Subject) {
      fields.push("Subject", message.Subject);
    }
    fields.push("Timestamp", message.Timestamp);
    fields.push("TopicArn", message.TopicArn);
    fields.push("Type", message.Type);
  } else {
    fields.push("Message", message.Message);
    fields.push("MessageId", message.MessageId);
    fields.push("SubscribeURL", message.SubscribeURL || "");
    fields.push("Timestamp", message.Timestamp);
    fields.push("Token", message.Token || "");
    fields.push("TopicArn", message.TopicArn);
    fields.push("Type", message.Type);
  }
  return fields.join("\n") + "\n";
}
async function verifySNSSignature(message, userAgent) {
  try {
    if (!message.SigningCertURL || !message.Signature || !message.Type) {
      console.error("Missing required SNS message fields");
      return false;
    }
    if (message.SignatureVersion !== "1" && message.SignatureVersion !== "2") {
      console.error("Unsupported signature version:", message.SignatureVersion);
      return false;
    }
    const cert = await getCertificate(message.SigningCertURL, userAgent);
    const stringToSign = buildStringToSign(message);
    const algorithm = message.SignatureVersion === "2" ? "SHA256" : "SHA1";
    const verifier = crypto.createVerify(algorithm);
    verifier.update(stringToSign);
    const signatureBuffer = Buffer.from(message.Signature, "base64");
    const isValid = verifier.verify(cert, signatureBuffer);
    if (!isValid) {
      console.error("SNS signature verification failed with algorithm:", algorithm);
    }
    return isValid;
  } catch (err) {
    console.error("SNS verification error:", err);
    return false;
  }
}
function validateTopicArn(topicArn, expectedAccount, expectedRegion, allowedTopics) {
  try {
    const parts = topicArn.split(":");
    if (parts.length !== 6 || parts[0] !== "arn" || parts[2] !== "sns") {
      console.error("Invalid TopicArn format:", topicArn);
      return false;
    }
    const [, , , region, account, topicName] = parts;
    if (expectedAccount && account !== expectedAccount) {
      console.error("TopicArn account mismatch:", account, "expected:", expectedAccount);
      return false;
    }
    if (expectedRegion && region !== expectedRegion) {
      console.error("TopicArn region mismatch:", region, "expected:", expectedRegion);
      return false;
    }
    if (allowedTopics && allowedTopics.length > 0 && !allowedTopics.includes(topicName)) {
      console.error("TopicArn topic not in allowlist:", topicName);
      return false;
    }
    return true;
  } catch {
    console.error("TopicArn validation error:", topicArn);
    return false;
  }
}
async function verifySNSMessage(message, options) {
  const signatureValid = await verifySNSSignature(message, options?.userAgent);
  if (!signatureValid) {
    return { valid: false, error: "Invalid signature" };
  }
  if (options) {
    const topicValid = validateTopicArn(
      message.TopicArn,
      options.expectedAccount,
      options.expectedRegion,
      options.allowedTopics
    );
    if (!topicValid) {
      return { valid: false, error: "Invalid topic ARN" };
    }
  }
  return { valid: true };
}

exports.validateTopicArn = validateTopicArn;
exports.verifySNSMessage = verifySNSMessage;
exports.verifySNSSignature = verifySNSSignature;
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map