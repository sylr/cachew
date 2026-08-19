package tokensource

import (
	"context"
	"time"

	"github.com/alecthomas/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// Bounds imposed by the GetWebIdentityToken API.
const (
	MinTokenDuration = 60 * time.Second
	MaxTokenDuration = 3600 * time.Second
)

// AWSSTSConfig mints tokens with sts:GetWebIdentityToken, which returns a JWT
// signed by AWS and verifiable through the account's OIDC issuer.
type AWSSTSConfig struct {
	Region  string            `hcl:"region,optional" help:"AWS region to call. GetWebIdentityToken is not available on the global STS endpoint."`
	Profile string            `hcl:"profile,optional" help:"Shared config profile to resolve credentials from."`
	Tags    map[string]string `hcl:"tags,optional" help:"Request tags, which appear as request_tags claims in the token."`

	AssumeRoles []AssumeRoleConfig `hcl:"assume-role,block,optional"`
}

// AssumeRoleConfig is one link in an assume-role chain evaluated in order, each
// role assumed with the credentials produced by the previous one.
type AssumeRoleConfig struct {
	RoleARN     string        `hcl:"role-arn" help:"Role to assume."`
	SessionName string        `hcl:"session-name,optional" help:"Role session name."`
	Duration    time.Duration `hcl:"duration,optional" help:"Role session duration."`
	ExternalID  string        `hcl:"external-id,optional" help:"External ID required by the role's trust policy."`
}

// stsAPI is the slice of the STS client this package uses, so tests can supply a
// fake instead of reaching AWS.
type stsAPI interface {
	GetWebIdentityToken(ctx context.Context, in *sts.GetWebIdentityTokenInput, opts ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error)
}

type awsSTSSource struct {
	client    stsAPI
	audience  []string
	algorithm string
	duration  time.Duration
	tags      []ststypes.Tag
}

func newAWSSTS(ctx context.Context, cfg Config, awsCfg AWSSTSConfig) (Source, error) {
	// Validate before touching AWS so a configuration mistake is reported as such
	// rather than as a credential-resolution failure.
	if _, err := newAWSSTSWithClient(cfg, nil); err != nil {
		return nil, err
	}
	client, err := newSTSClient(ctx, awsCfg)
	if err != nil {
		return nil, err
	}
	return newAWSSTSWithClient(cfg, client)
}

// newAWSSTSWithClient builds the source around an already-resolved STS client.
func newAWSSTSWithClient(cfg Config, client stsAPI) (*awsSTSSource, error) {
	if len(cfg.Audience) == 0 {
		return nil, errors.New("oidc: audience is required for the aws-sts token source")
	}
	algorithm := cfg.SigningAlgorithm
	if algorithm == "" {
		algorithm = "RS256"
	}
	if algorithm != "RS256" && algorithm != "ES384" {
		return nil, errors.Errorf("oidc: signing-algorithm must be RS256 or ES384, got %q", algorithm)
	}
	duration, err := clampDuration(cfg.Duration)
	if err != nil {
		return nil, err
	}

	var tags []ststypes.Tag
	if cfg.AWSSTS != nil {
		tags = make([]ststypes.Tag, 0, len(cfg.AWSSTS.Tags))
		for key, value := range cfg.AWSSTS.Tags {
			tags = append(tags, ststypes.Tag{Key: aws.String(key), Value: aws.String(value)})
		}
		for _, role := range cfg.AWSSTS.AssumeRoles {
			if role.RoleARN == "" {
				return nil, errors.New("oidc: assume-role requires role-arn")
			}
		}
	}

	return &awsSTSSource{
		client:    client,
		audience:  cfg.Audience,
		algorithm: algorithm,
		duration:  duration,
		tags:      tags,
	}, nil
}

// clampDuration validates the requested lifetime against the API's limits. An
// out-of-range value is an error rather than being silently adjusted, so the
// operator finds out that the token will not live as long as they asked.
func clampDuration(d time.Duration) (time.Duration, error) {
	if d == 0 {
		return 0, nil
	}
	if d < MinTokenDuration || d > MaxTokenDuration {
		return 0, errors.Errorf("oidc: duration must be between %s and %s, got %s", MinTokenDuration, MaxTokenDuration, d)
	}
	return d, nil
}

// newSTSClient resolves AWS credentials, walking any configured assume-role chain.
func newSTSClient(ctx context.Context, cfg AWSSTSConfig) (stsAPI, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	if cfg.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.Profile))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, errors.Errorf("load AWS configuration: %w", err)
	}

	for _, role := range cfg.AssumeRoles {
		provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsCfg), role.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			if role.SessionName != "" {
				o.RoleSessionName = role.SessionName
			}
			if role.Duration > 0 {
				o.Duration = role.Duration
			}
			if role.ExternalID != "" {
				o.ExternalID = aws.String(role.ExternalID)
			}
		})
		awsCfg.Credentials = aws.NewCredentialsCache(provider)
	}

	if awsCfg.Region == "" {
		return nil, errors.New("oidc: aws-sts requires a region, because GetWebIdentityToken is not available on the global STS endpoint")
	}
	return sts.NewFromConfig(awsCfg), nil
}

func (s *awsSTSSource) Token(ctx context.Context) (string, error) {
	in := &sts.GetWebIdentityTokenInput{
		Audience:         s.audience,
		SigningAlgorithm: aws.String(s.algorithm),
		Tags:             s.tags,
	}
	if s.duration > 0 {
		in.DurationSeconds = aws.Int32(int32(s.duration.Seconds()))
	}

	out, err := s.client.GetWebIdentityToken(ctx, in)
	if err != nil {
		// The error text is preserved verbatim: the most common first-run failure
		// is OutboundWebIdentityFederationDisabled, and AWS's own wording is what
		// leads the operator to the console setting that fixes it.
		return "", errors.Errorf("mint AWS web identity token: %w", err)
	}
	if out.WebIdentityToken == nil || *out.WebIdentityToken == "" {
		return "", errors.New("AWS returned an empty web identity token")
	}
	return *out.WebIdentityToken, nil
}
