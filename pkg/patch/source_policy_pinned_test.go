package patch

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/sourcepolicy"
	policytypes "github.com/moby/buildkit/sourcepolicy/pb"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

// An exact-tag ALLOW after a wildcard DENY authorizes the requested input. Copa
// reads that input by digest, so the pinned reference must stay allowed, while
// every other source keeps the policy's own decision.
func TestAuthorizePinnedInput(t *testing.T) {
	const repo = "example.com/team/app"
	child := repo + "@" + digest.FromString("captured child").String()
	other := repo + "@" + digest.FromString("unrelated digest").String()
	allowlist := func() *policytypes.Policy {
		return &policytypes.Policy{Rules: []*policytypes.Rule{
			{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: "docker-image://" + repo + "*", MatchType: policytypes.MatchType_WILDCARD}},
			{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{Identifier: "docker-image://" + repo + ":approved"}},
		}}
	}
	allowed := func(t *testing.T, policy *policytypes.Policy, ref string) bool {
		t.Helper()
		id, err := imageSourceIdentifier(ref)
		require.NoError(t, err)
		ok, err := policyAllowsUnchanged(t.Context(), policy, id)
		require.NoError(t, err)
		return ok
	}

	t.Run("allowed tag carries to its pinned child", func(t *testing.T) {
		policy := allowlist()
		require.False(t, allowed(t, policy, child), "control: the pinned child is denied as written")
		got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child, child)
		require.NoError(t, err)
		require.True(t, allowed(t, got, child))
		require.Len(t, got.Rules, len(policy.Rules)+1, "one exact rule per pinned reference")
		require.Equal(t, policytypes.MatchType_EXACT, got.Rules[len(got.Rules)-1].Selector.MatchType)
		require.False(t, allowed(t, got, other), "other digests in the repository stay denied")
		require.False(t, allowed(t, got, repo+":unapproved"), "other tags stay denied")
		require.True(t, allowed(t, got, "docker.io/library/busybox:latest"), "unrelated tooling keeps the policy's decision")
		require.Len(t, policy.Rules, 2, "the caller's policy is not modified")
	})

	t.Run("denied input is not authorized", func(t *testing.T) {
		policy := allowlist()
		got, err := authorizePinnedInput(t.Context(), policy, repo+":unapproved", child)
		require.NoError(t, err)
		require.Same(t, policy, got)
		require.False(t, allowed(t, got, child))
	})

	t.Run("converted input keeps the policy", func(t *testing.T) {
		policy := &policytypes.Policy{Rules: []*policytypes.Rule{{
			Action: policytypes.PolicyAction_CONVERT, Selector: &policytypes.Selector{Identifier: "docker-image://" + repo + ":approved"},
			Updates: &policytypes.Update{Identifier: "docker-image://" + other},
		}}}
		got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
		require.NoError(t, err)
		require.Same(t, policy, got)
	})

	t.Run("unrelated digest denial does not block the allowed pin", func(t *testing.T) {
		policy := allowlist()
		policy.Rules = append(policy.Rules, &policytypes.Rule{
			Action:   policytypes.PolicyAction_DENY,
			Selector: &policytypes.Selector{Identifier: imageSourceScheme + other, MatchType: policytypes.MatchType_EXACT},
		})
		got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
		require.NoError(t, err)
		require.True(t, allowed(t, got, child))
		require.False(t, allowed(t, got, other))
	})

	t.Run("allowed pin conversion keeps the policy", func(t *testing.T) {
		policy := &policytypes.Policy{Rules: []*policytypes.Rule{{
			Action:   policytypes.PolicyAction_CONVERT,
			Selector: &policytypes.Selector{Identifier: imageSourceScheme + child, MatchType: policytypes.MatchType_EXACT},
			Updates:  &policytypes.Update{Identifier: imageSourceScheme + other},
		}}}
		got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
		require.NoError(t, err)
		require.Same(t, policy, got)
		op := imageSourceOp(imageSourceScheme + child)
		_, err = sourcepolicy.NewEngine([]*policytypes.Policy{got}).Evaluate(t.Context(), op)
		require.NoError(t, err)
		require.Equal(t, imageSourceScheme+other, op.Identifier)
	})

	t.Run("already allowed or no policy needs no rule", func(t *testing.T) {
		open := &policytypes.Policy{Rules: []*policytypes.Rule{
			{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: "docker-image://example.com/other*", MatchType: policytypes.MatchType_WILDCARD}},
		}}
		got, err := authorizePinnedInput(t.Context(), open, repo+":approved", child)
		require.NoError(t, err)
		require.Same(t, open, got)
		got, err = authorizePinnedInput(t.Context(), nil, repo+":approved", child)
		require.NoError(t, err)
		require.Nil(t, got)
	})

	t.Run("unpinned reference is left to the policy", func(t *testing.T) {
		policy := allowlist()
		got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", repo+":approved")
		require.NoError(t, err)
		require.Same(t, policy, got)
	})

	t.Run("BuildKit engine denies the pinned child without the rule", func(t *testing.T) {
		_, err := sourcepolicy.NewEngine([]*policytypes.Policy{allowlist()}).Evaluate(t.Context(), imageSourceOp("docker-image://"+child))
		require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied)
	})
}

func TestAuthorizePinnedInputPreservesDigestDenials(t *testing.T) {
	const repo = "example.com/team/app"
	child := repo + "@" + digest.FromString("blocked child").String()
	other := repo + "@" + digest.FromString("allowed child").String()
	root := digest.FromString("original index").String()
	for _, requested := range []string{repo + ":approved", repo + ":approved@" + root, repo + "@" + root} {
		for _, explicit := range []bool{false, true} {
			for _, denyFirst := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/explicit=%t/deny-first=%t", requested, explicit, denyFirst), func(t *testing.T) {
					for _, matchType := range []policytypes.MatchType{policytypes.MatchType_EXACT, policytypes.MatchType_WILDCARD, policytypes.MatchType_REGEX} {
						t.Run(matchType.String(), func(t *testing.T) {
							selector := imageSourceScheme + child
							switch matchType {
							case policytypes.MatchType_WILDCARD:
								selector = selector[:len(selector)-8] + "*"
							case policytypes.MatchType_REGEX:
								selector = "^" + regexp.QuoteMeta(selector) + "$"
							}
							deny := &policytypes.Rule{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: selector, MatchType: matchType}}
							policy := &policytypes.Policy{}
							if denyFirst {
								policy.Rules = append(policy.Rules, deny)
							}
							if explicit {
								policy.Rules = append(policy.Rules,
									&policytypes.Rule{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + "*", MatchType: policytypes.MatchType_WILDCARD}},
									&policytypes.Rule{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{Identifier: imageSourceScheme + requested}},
								)
							}
							if !denyFirst {
								policy.Rules = append(policy.Rules, deny)
							}
							allowed, err := policyAllowsUnchanged(t.Context(), policy, imageSourceScheme+requested)
							require.NoError(t, err)
							require.True(t, allowed, "control: the requested locator is allowed")
							before := len(policy.Rules)
							got, err := authorizePinnedInput(t.Context(), policy, requested, other, child)
							require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied)
							require.Nil(t, got, "do not return a partially authorized policy")
							require.Len(t, policy.Rules, before, "do not mutate the caller's policy")
						})
					}
				})
			}
		}
	}
}

func TestAuthorizePinnedInputConditionalDenial(t *testing.T) {
	const repo = "example.com/team/app"
	child := repo + "@" + digest.FromString("conditional child").String()
	policy := &policytypes.Policy{Rules: []*policytypes.Rule{
		{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + "*", MatchType: policytypes.MatchType_WILDCARD}},
		{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + ":approved"}},
		{
			Action: policytypes.PolicyAction_DENY,
			Selector: &policytypes.Selector{
				Identifier:  imageSourceScheme + child,
				Constraints: []*policytypes.AttrConstraint{{Key: pb.AttrImageRecordType, Value: "internal", Condition: policytypes.AttrMatch_EQUAL}},
			},
		},
	}}
	got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
	require.NoError(t, err)
	_, err = sourcepolicy.NewEngine([]*policytypes.Policy{got}).Evaluate(t.Context(), imageSourceOp(imageSourceScheme+child))
	require.NoError(t, err, "the evaluated input attributes retain their permission")
	op := imageSourceOp(imageSourceScheme + child)
	op.Attrs[pb.AttrImageRecordType] = "internal"
	_, err = sourcepolicy.NewEngine([]*policytypes.Policy{got}).Evaluate(t.Context(), op)
	require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied, "a different source operation keeps its conditional denial")
}

func TestAuthorizePinnedInputConvertedDenial(t *testing.T) {
	const repo = "example.com/team/app"
	child := repo + "@" + digest.FromString("converted child").String()
	policy := &policytypes.Policy{Rules: []*policytypes.Rule{
		{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + "*", MatchType: policytypes.MatchType_WILDCARD}},
		{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + ":approved"}},
		{
			Action:   policytypes.PolicyAction_CONVERT,
			Selector: &policytypes.Selector{Identifier: imageSourceScheme + child},
			Updates:  &policytypes.Update{Attrs: map[string]string{pb.AttrImageResolveMode: "pull"}},
		},
	}}
	_, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
	require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied, "a denied conversion must not inherit tag permission")
}

func TestAuthorizePinnedInputOverlappingDenials(t *testing.T) {
	const repo = "example.com/team/app"
	root := digest.FromString("index exemption").String()
	child := repo + "@" + digest.FromString("denied child").String()
	for _, requested := range []string{repo + ":approved", repo + ":approved@" + root, repo + "@" + root} {
		for _, kind := range []string{"digest class", "digest text", "grouped regex"} {
			t.Run(requested+"/"+kind, func(t *testing.T) {
				selector := &policytypes.Selector{Identifier: imageSourceScheme + repo + "*@sha256:*", MatchType: policytypes.MatchType_WILDCARD}
				if kind == "digest text" {
					selector.Identifier = imageSourceScheme + repo + "*sha256:*"
				}
				if kind == "grouped regex" {
					selector = &policytypes.Selector{
						Identifier: "^(" + regexp.QuoteMeta(imageSourceScheme+requested) + "|" + regexp.QuoteMeta(imageSourceScheme+child) + ")$",
						MatchType:  policytypes.MatchType_REGEX,
					}
				}
				policy := &policytypes.Policy{Rules: []*policytypes.Rule{
					{Action: policytypes.PolicyAction_DENY, Selector: selector},
					{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{Identifier: imageSourceScheme + requested, MatchType: policytypes.MatchType_EXACT}},
				}}
				allowed, err := policyAllowsUnchanged(t.Context(), policy, imageSourceScheme+requested)
				require.NoError(t, err)
				require.True(t, allowed)
				_, err = sourcepolicy.NewEngine([]*policytypes.Policy{policy}).Evaluate(t.Context(), imageSourceOp(imageSourceScheme+child))
				require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied)
				got, err := authorizePinnedInput(t.Context(), policy, requested, child)
				require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied)
				require.Nil(t, got)
			})
		}
	}
}

type pinnedPolicyMetadataResolver struct {
	policy *policytypes.Policy
}

func (r pinnedPolicyMetadataResolver) ResolveSourceMetadata(ctx context.Context, op *pb.SourceOp, _ sourceresolver.Opt) (*sourceresolver.MetaResponse, error) {
	if _, err := sourcepolicy.NewEngine([]*policytypes.Policy{r.policy}).Evaluate(ctx, op); err != nil {
		return nil, err
	}
	return &sourceresolver.MetaResponse{Op: op, Image: &sourceresolver.ResolveImageResponse{Config: []byte("{}")}}, nil
}

func TestAuthorizePinnedInputMetadataAttributes(t *testing.T) {
	const repo = "example.com/team/app"
	child := repo + "@" + digest.FromString("metadata child").String()
	for _, condition := range []policytypes.AttrMatch{policytypes.AttrMatch_EQUAL, policytypes.AttrMatch_NOTEQUAL, policytypes.AttrMatch_MATCHES} {
		t.Run(condition.String(), func(t *testing.T) {
			policy := &policytypes.Policy{Rules: []*policytypes.Rule{
				{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + "*", MatchType: policytypes.MatchType_WILDCARD}},
				{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + ":approved"}},
				{
					Action: policytypes.PolicyAction_DENY,
					Selector: &policytypes.Selector{
						Identifier:  "docker-image://example.com/tooling:latest",
						Constraints: []*policytypes.AttrConstraint{{Key: pb.AttrImageResolveMode, Value: "pull", Condition: condition}},
					},
				},
			}}
			got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
			require.NoError(t, err)
			_, err = sourcepolicy.NewEngine([]*policytypes.Policy{got}).Evaluate(t.Context(), imageSourceOp(imageSourceScheme+child))
			require.NoError(t, err, "LLB permission is retained")
			resolver := sourceresolver.NewImageMetaResolver(pinnedPolicyMetadataResolver{policy: got})
			_, _, _, err = resolver.ResolveImageConfig(t.Context(), child, sourceresolver.Opt{
				ImageOpt: &sourceresolver.ResolveImageOpt{ResolveMode: llb.ResolveModePreferLocal.String()},
			})
			require.NoError(t, err, "the real metadata adapter omits source attributes")
		})
	}
}

func TestAuthorizePinnedInputConditionalRepresentations(t *testing.T) {
	const repo = "example.com/team/app"
	child := repo + "@" + digest.FromString("attribute-sensitive child").String()
	for _, tc := range []struct {
		name      string
		condition policytypes.AttrMatch
		value     string
	}{
		{"equal", policytypes.AttrMatch_EQUAL, "pull"},
		{"not-equal", policytypes.AttrMatch_NOTEQUAL, ""},
		{"matches", policytypes.AttrMatch_MATCHES, "^pull$"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := pb.AttrImageRecordType
			if tc.condition != policytypes.AttrMatch_NOTEQUAL {
				key = pb.AttrImageResolveMode
			}
			policy := &policytypes.Policy{Rules: []*policytypes.Rule{
				{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + "*", MatchType: policytypes.MatchType_WILDCARD}},
				{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + ":approved"}},
				{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{
					Identifier:  imageSourceScheme + child,
					Constraints: []*policytypes.AttrConstraint{{Key: key, Value: tc.value, Condition: tc.condition}},
				}},
			}}
			before := policy.CloneVT()
			got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
			require.NoError(t, err)
			for _, op := range []*pb.SourceOp{imageSourceOp(imageSourceScheme + child), {Identifier: imageSourceScheme + child}} {
				_, err := sourcepolicy.NewEngine([]*policytypes.Policy{got}).Evaluate(t.Context(), op)
				require.NoError(t, err, "both actual BuildKit representations retain permission")
			}
			op := imageSourceOp(imageSourceScheme + child)
			op.Attrs[key] = "pull"
			_, err = sourcepolicy.NewEngine([]*policytypes.Policy{got}).Evaluate(t.Context(), op)
			require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied)
			require.Equal(t, before, policy, "caller-owned rules remain unchanged")
		})
	}
}

func TestAuthorizePinnedInputKeepsConditionalBlanketDenial(t *testing.T) {
	const repo = "example.com/team/app"
	child := repo + "@" + digest.FromString("conditional blanket child").String()
	policy := &policytypes.Policy{Rules: []*policytypes.Rule{
		{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{
			Identifier: imageSourceScheme + repo + "*", MatchType: policytypes.MatchType_WILDCARD,
			Constraints: []*policytypes.AttrConstraint{{Key: pb.AttrImageResolveMode, Value: "local", Condition: policytypes.AttrMatch_EQUAL}},
		}},
		{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + ":approved"}},
	}}
	_, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
	require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied)
}

func TestAuthorizePinnedInputRequiresMetadataPermission(t *testing.T) {
	const repo = "example.com/team/app"
	child := repo + "@" + digest.FromString("metadata permission child").String()
	policy := &policytypes.Policy{Rules: []*policytypes.Rule{
		{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + "*", MatchType: policytypes.MatchType_WILDCARD}},
		{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{
			Identifier:  imageSourceScheme + repo + ":approved",
			Constraints: []*policytypes.AttrConstraint{{Key: pb.AttrImageResolveMode, Value: "local", Condition: policytypes.AttrMatch_EQUAL}},
		}},
	}}
	_, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
	require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied, "LLB permission alone must not grant metadata admission")
}

func TestAuthorizePinnedInputRespectsExplicitPinAllow(t *testing.T) {
	const repo = "example.com/team/app"
	child := repo + "@" + digest.FromString("explicitly allowed child").String()
	policy := &policytypes.Policy{Rules: []*policytypes.Rule{
		{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: imageSourceScheme + child}},
		{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{Identifier: imageSourceScheme + child}},
	}}
	got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
	require.NoError(t, err)
	require.Same(t, policy, got, "native last-matching-rule permission needs no inheritance")
}

func TestAuthorizePinnedInputNoopConversion(t *testing.T) {
	const repo = "example.com/team/app"
	child := repo + "@" + digest.FromString("no-op conversion child").String()
	policy := &policytypes.Policy{Rules: []*policytypes.Rule{
		{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + "*", MatchType: policytypes.MatchType_WILDCARD}},
		{
			Action: policytypes.PolicyAction_CONVERT, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + ":approved"},
			Updates: &policytypes.Update{Attrs: map[string]string{pb.AttrImageResolveMode: "local"}},
		},
		{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + ":approved"}},
	}}
	got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
	require.NoError(t, err)
	for _, op := range []*pb.SourceOp{imageSourceOp(imageSourceScheme + child), {Identifier: imageSourceScheme + child}} {
		_, err := sourcepolicy.NewEngine([]*policytypes.Policy{got}).Evaluate(t.Context(), op)
		require.NoError(t, err)
	}
}

func TestAuthorizePinnedInputSelectorCacheIsolation(t *testing.T) {
	const repo = "example.com/team/app"
	child := repo + "@" + digest.FromString("selector cache child").String()
	id := imageSourceScheme + child
	policy := &policytypes.Policy{Rules: []*policytypes.Rule{
		{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + "*", MatchType: policytypes.MatchType_WILDCARD}},
		{Action: policytypes.PolicyAction_ALLOW, Selector: &policytypes.Selector{Identifier: imageSourceScheme + repo + ":approved"}},
		{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{
			Identifier: id, Constraints: []*policytypes.AttrConstraint{{Key: pb.AttrImageResolveMode, Value: "pull", Condition: policytypes.AttrMatch_EQUAL}},
		}},
		{Action: policytypes.PolicyAction_DENY, Selector: &policytypes.Selector{
			Identifier: "^" + regexp.QuoteMeta(id) + "$", MatchType: policytypes.MatchType_REGEX,
			Constraints: []*policytypes.AttrConstraint{{Key: pb.AttrImageRecordType, Value: "internal", Condition: policytypes.AttrMatch_EQUAL}},
		}},
	}}
	got, err := authorizePinnedInput(t.Context(), policy, repo+":approved", child)
	require.NoError(t, err)
	used := map[string]struct{}{}
	for _, rule := range policy.Rules {
		used[rule.Selector.MatchType.String()+" "+rule.Selector.Identifier] = struct{}{}
	}
	for _, rule := range got.Rules[len(policy.Rules):] {
		key := rule.Selector.MatchType.String() + " " + rule.Selector.Identifier
		_, exists := used[key]
		require.False(t, exists, "inherited constraints must have a unique legacy selector-cache key")
		used[key] = struct{}{}
	}
	for _, op := range []*pb.SourceOp{imageSourceOp(id), {Identifier: id}} {
		_, err := sourcepolicy.NewEngine([]*policytypes.Policy{got}).Evaluate(t.Context(), op)
		require.NoError(t, err)
	}
	for _, attr := range []string{pb.AttrImageResolveMode, pb.AttrImageRecordType} {
		op := imageSourceOp(id)
		if attr == pb.AttrImageResolveMode {
			op.Attrs[attr] = "pull"
		} else {
			op.Attrs[attr] = "internal"
		}
		_, err := sourcepolicy.NewEngine([]*policytypes.Policy{got}).Evaluate(t.Context(), op)
		require.ErrorIs(t, err, sourcepolicy.ErrSourceDenied)
	}
}
