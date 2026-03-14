/**
 * AWS SNS Message Signature Verification
 *
 * Implements full cryptographic verification of SNS messages per AWS documentation:
 * https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
 */
interface SNSMessage {
    Type: 'Notification' | 'SubscriptionConfirmation' | 'UnsubscribeConfirmation';
    MessageId: string;
    TopicArn: string;
    Subject?: string;
    Message: string;
    Timestamp: string;
    SignatureVersion: string;
    Signature: string;
    SigningCertURL: string;
    SubscribeURL?: string;
    UnsubscribeURL?: string;
    Token?: string;
}
interface VerifySNSOptions {
    expectedAccount?: string;
    expectedRegion?: string;
    allowedTopics?: string[];
    /** Custom User-Agent for certificate fetch requests */
    userAgent?: string;
}
/**
 * Verifies an SNS message signature
 */
declare function verifySNSSignature(message: SNSMessage, userAgent?: string): Promise<boolean>;
/**
 * Validates that a TopicArn belongs to the expected AWS account and region
 */
declare function validateTopicArn(topicArn: string, expectedAccount?: string, expectedRegion?: string, allowedTopics?: string[]): boolean;
/**
 * Full verification of an SNS message including signature and topic validation
 */
declare function verifySNSMessage(message: SNSMessage, options?: VerifySNSOptions): Promise<{
    valid: boolean;
    error?: string;
}>;

export { type SNSMessage, type VerifySNSOptions, validateTopicArn, verifySNSMessage, verifySNSSignature };
