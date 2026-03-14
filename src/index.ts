/**
 * AWS SNS Message Signature Verification
 *
 * Implements full cryptographic verification of SNS messages per AWS documentation:
 * https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
 */

import { createVerify, X509Certificate } from 'crypto'

// Cache for downloaded certificates (in-memory, per-instance)
const certCache = new Map<string, { cert: string; expires: number }>()
const CERT_CACHE_TTL = 60 * 60 * 1000 // 1 hour

// Valid AWS SNS certificate URL patterns
const VALID_CERT_URL_PATTERNS = [
  /^https:\/\/sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?\/SimpleNotificationService-[a-f0-9]+\.pem$/,
]

export interface SNSMessage {
  Type: 'Notification' | 'SubscriptionConfirmation' | 'UnsubscribeConfirmation'
  MessageId: string
  TopicArn: string
  Subject?: string
  Message: string
  Timestamp: string
  SignatureVersion: string
  Signature: string
  SigningCertURL: string
  SubscribeURL?: string
  UnsubscribeURL?: string
  Token?: string
}

export interface VerifySNSOptions {
  expectedAccount?: string
  expectedRegion?: string
  allowedTopics?: string[]
  /** Custom User-Agent for certificate fetch requests */
  userAgent?: string
}

/**
 * Validates that the certificate URL is from AWS
 */
function isValidCertUrl(url: string): boolean {
  try {
    const parsed = new URL(url)

    // Must be HTTPS
    if (parsed.protocol !== 'https:') {
      console.error('SNS cert URL not HTTPS:', url)
      return false
    }

    // Must be from amazonaws.com
    if (!parsed.hostname.endsWith('.amazonaws.com') && !parsed.hostname.endsWith('.amazonaws.com.cn')) {
      console.error('SNS cert URL not from AWS:', url)
      return false
    }

    // Must match expected pattern
    const matches = VALID_CERT_URL_PATTERNS.some(pattern => pattern.test(url))
    if (!matches) {
      console.error('SNS cert URL does not match expected pattern:', url)
      return false
    }

    return true
  } catch {
    console.error('Invalid SNS cert URL:', url)
    return false
  }
}

/**
 * Downloads and caches the signing certificate from AWS
 */
async function getCertificate(url: string, userAgent?: string): Promise<string> {
  // Check cache first
  const cached = certCache.get(url)
  if (cached && cached.expires > Date.now()) {
    return cached.cert
  }

  // Validate URL before fetching
  if (!isValidCertUrl(url)) {
    throw new Error('Invalid certificate URL')
  }

  // Fetch certificate
  const response = await fetch(url, {
    headers: { 'User-Agent': userAgent ?? 'avd-sns-verify/1.0' }
  })

  if (!response.ok) {
    throw new Error(`Failed to fetch certificate: ${response.status}`)
  }

  const cert = await response.text()

  // Validate it's a valid PEM certificate
  if (!cert.includes('-----BEGIN CERTIFICATE-----')) {
    throw new Error('Invalid certificate format')
  }

  // Validate certificate is from Amazon
  try {
    const x509 = new X509Certificate(cert)
    const issuer = x509.issuer

    // Check that issuer is Amazon
    if (!issuer.includes('Amazon') && !issuer.includes('AWS')) {
      console.error('Certificate not issued by Amazon:', issuer)
      throw new Error('Certificate not issued by Amazon')
    }

    // Check certificate is not expired
    const validTo = new Date(x509.validTo)
    if (validTo < new Date()) {
      throw new Error('Certificate has expired')
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes('Amazon')) {
      throw err
    }
    console.error('Certificate validation error:', err)
    throw new Error('Invalid certificate')
  }

  // Cache the certificate
  certCache.set(url, {
    cert,
    expires: Date.now() + CERT_CACHE_TTL
  })

  return cert
}

/**
 * Builds the string to sign based on message type
 * Order of fields matters for signature verification
 */
function buildStringToSign(message: SNSMessage): string {
  const fields: string[] = []

  if (message.Type === 'Notification') {
    // Notification messages
    fields.push('Message', message.Message)
    fields.push('MessageId', message.MessageId)
    if (message.Subject) {
      fields.push('Subject', message.Subject)
    }
    fields.push('Timestamp', message.Timestamp)
    fields.push('TopicArn', message.TopicArn)
    fields.push('Type', message.Type)
  } else {
    // SubscriptionConfirmation or UnsubscribeConfirmation
    fields.push('Message', message.Message)
    fields.push('MessageId', message.MessageId)
    fields.push('SubscribeURL', message.SubscribeURL || '')
    fields.push('Timestamp', message.Timestamp)
    fields.push('Token', message.Token || '')
    fields.push('TopicArn', message.TopicArn)
    fields.push('Type', message.Type)
  }

  // Each field on its own line, key and value separated by newline
  return fields.join('\n') + '\n'
}

/**
 * Verifies an SNS message signature
 */
export async function verifySNSSignature(message: SNSMessage, userAgent?: string): Promise<boolean> {
  try {
    // Validate required fields
    if (!message.SigningCertURL || !message.Signature || !message.Type) {
      console.error('Missing required SNS message fields')
      return false
    }

    // Support both SignatureVersion 1 (SHA1) and 2 (SHA256)
    if (message.SignatureVersion !== '1' && message.SignatureVersion !== '2') {
      console.error('Unsupported signature version:', message.SignatureVersion)
      return false
    }

    // Get the signing certificate
    const cert = await getCertificate(message.SigningCertURL, userAgent)

    // Build the string to sign
    const stringToSign = buildStringToSign(message)

    // Verify the signature - use SHA256 for SignatureVersion 2
    const algorithm = message.SignatureVersion === '2' ? 'SHA256' : 'SHA1'
    const verifier = createVerify(algorithm)
    verifier.update(stringToSign)

    const signatureBuffer = Buffer.from(message.Signature, 'base64')
    const isValid = verifier.verify(cert, signatureBuffer)

    if (!isValid) {
      console.error('SNS signature verification failed with algorithm:', algorithm)
    }

    return isValid
  } catch (err) {
    console.error('SNS verification error:', err)
    return false
  }
}

/**
 * Validates that a TopicArn belongs to the expected AWS account and region
 */
export function validateTopicArn(
  topicArn: string,
  expectedAccount?: string,
  expectedRegion?: string,
  allowedTopics?: string[]
): boolean {
  try {
    // Parse ARN: arn:aws:sns:region:account-id:topic-name
    const parts = topicArn.split(':')
    if (parts.length !== 6 || parts[0] !== 'arn' || parts[2] !== 'sns') {
      console.error('Invalid TopicArn format:', topicArn)
      return false
    }

    const [, , , region, account, topicName] = parts

    // Validate account if specified
    if (expectedAccount && account !== expectedAccount) {
      console.error('TopicArn account mismatch:', account, 'expected:', expectedAccount)
      return false
    }

    // Validate region if specified
    if (expectedRegion && region !== expectedRegion) {
      console.error('TopicArn region mismatch:', region, 'expected:', expectedRegion)
      return false
    }

    // Validate topic name if allowlist specified
    if (allowedTopics && allowedTopics.length > 0 && !allowedTopics.includes(topicName)) {
      console.error('TopicArn topic not in allowlist:', topicName)
      return false
    }

    return true
  } catch {
    console.error('TopicArn validation error:', topicArn)
    return false
  }
}

/**
 * Full verification of an SNS message including signature and topic validation
 */
export async function verifySNSMessage(
  message: SNSMessage,
  options?: VerifySNSOptions
): Promise<{ valid: boolean; error?: string }> {
  // Verify signature
  const signatureValid = await verifySNSSignature(message, options?.userAgent)
  if (!signatureValid) {
    return { valid: false, error: 'Invalid signature' }
  }

  // Validate topic ARN
  if (options) {
    const topicValid = validateTopicArn(
      message.TopicArn,
      options.expectedAccount,
      options.expectedRegion,
      options.allowedTopics
    )
    if (!topicValid) {
      return { valid: false, error: 'Invalid topic ARN' }
    }
  }

  return { valid: true }
}
