package tokensource_test

import (
	"context"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/block/cachew/internal/tokensource"
)

// fakeSTS records the request it was given and returns a canned response.
type fakeSTS struct {
	input *sts.GetWebIdentityTokenInput
	token string
	err   error
}

func (f *fakeSTS) GetWebIdentityToken(_ context.Context, in *sts.GetWebIdentityTokenInput, _ ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error) {
	f.input = in
	if f.err != nil {
		return nil, f.err
	}
	out := &sts.GetWebIdentityTokenOutput{}
	if f.token != "" {
		out.WebIdentityToken = aws.String(f.token)
	}
	return out, nil
}

func TestAWSSTSBuildsRequest(t *testing.T) {
	token := makeToken(t, time.Now().Add(time.Hour), "")
	fake := &fakeSTS{token: token}

	source, err := tokensource.NewAWSSTSForTest(tokensource.Config{
		Audience:         []string{"https://cachew.example.com", "https://second.example.com"},
		SigningAlgorithm: "ES384",
		Duration:         20 * time.Minute,
		AWSSTS: &tokensource.AWSSTSConfig{
			Region: "eu-west-1",
			Tags:   map[string]string{"team": "platform"},
		},
	}, fake)
	assert.NoError(t, err)

	got, err := source.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, token, got)

	assert.Equal(t, []string{"https://cachew.example.com", "https://second.example.com"}, fake.input.Audience)
	assert.Equal(t, "ES384", *fake.input.SigningAlgorithm)
	assert.Equal(t, int32(1200), *fake.input.DurationSeconds)
	assert.Equal(t, 1, len(fake.input.Tags))
	assert.Equal(t, "team", *fake.input.Tags[0].Key)
	assert.Equal(t, "platform", *fake.input.Tags[0].Value)
}

func TestAWSSTSOmitsUnsetDuration(t *testing.T) {
	fake := &fakeSTS{token: makeToken(t, time.Now().Add(time.Hour), "")}
	source, err := tokensource.NewAWSSTSForTest(tokensource.Config{
		Audience: []string{"https://cachew.example.com"},
		AWSSTS:   &tokensource.AWSSTSConfig{Region: "eu-west-1"},
	}, fake)
	assert.NoError(t, err)

	_, err = source.Token(t.Context())
	assert.NoError(t, err)
	assert.Zero(t, fake.input.DurationSeconds)
	assert.Equal(t, "RS256", *fake.input.SigningAlgorithm)
}

func TestAWSSTSPropagatesError(t *testing.T) {
	fake := &fakeSTS{err: &outboundFederationDisabledError{}}
	source, err := tokensource.NewAWSSTSForTest(tokensource.Config{
		Audience: []string{"https://cachew.example.com"},
		AWSSTS:   &tokensource.AWSSTSConfig{Region: "eu-west-1"},
	}, fake)
	assert.NoError(t, err)

	_, err = source.Token(t.Context())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OutboundWebIdentityFederationDisabled")
}

type outboundFederationDisabledError struct{}

func (*outboundFederationDisabledError) Error() string {
	return "operation error STS: GetWebIdentityToken, OutboundWebIdentityFederationDisabled: outbound web identity federation is not enabled for this account"
}

func TestAWSSTSRejectsEmptyToken(t *testing.T) {
	fake := &fakeSTS{}
	source, err := tokensource.NewAWSSTSForTest(tokensource.Config{
		Audience: []string{"https://cachew.example.com"},
		AWSSTS:   &tokensource.AWSSTSConfig{Region: "eu-west-1"},
	}, fake)
	assert.NoError(t, err)

	_, err = source.Token(t.Context())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty web identity token")
}
