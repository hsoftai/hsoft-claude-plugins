package detect

// Category identifies the kind of secret a Finding represents. It is used both
// for audit logging and to build deterministic redaction placeholders.
type Category string

const (
	CategoryAWSAccessKey    Category = "AWS_ACCESS_KEY"
	CategoryAWSSecretKey    Category = "AWS_SECRET_KEY"
	CategoryGCPAPIKey       Category = "GCP_API_KEY"
	CategoryAzureStorageKey Category = "AZURE_STORAGE_KEY"
	CategoryJWT             Category = "JWT"
	CategoryGitHubToken     Category = "GITHUB_TOKEN"
	CategorySlackToken      Category = "SLACK_TOKEN"
	CategoryStripeKey       Category = "STRIPE_KEY"
	CategoryAnthropicKey    Category = "ANTHROPIC_KEY"
	CategoryPrivateKey      Category = "PRIVATE_KEY"
	CategoryPasswordURI     Category = "PASSWORD_URI"
	CategoryGenericSecret   Category = "GENERIC_SECRET"
)
