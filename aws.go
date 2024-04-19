package awspolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
)

// GetAWSPolicy retrieves an AWS policy by its ARN.
func GetAWSPolicy(ctx context.Context, svc *iam.IAM, policyArn string) (*Policy, error) {
	policy, err := svc.GetPolicyWithContext(ctx, &iam.GetPolicyInput{
		PolicyArn: aws.String(policyArn),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	policyVersion, err := svc.GetPolicyVersionWithContext(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: policy.Policy.Arn,
		VersionId: policy.Policy.DefaultVersionId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get policy version: %w", err)
	}

	escaped, err := url.QueryUnescape(*policyVersion.PolicyVersion.Document)
	if err != nil {
		return nil, fmt.Errorf("failed to unescape policy document: %w", err)
	}

	var p Policy
	if err := json.Unmarshal(json.RawMessage(escaped), &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy document: %w", err)
	}

	return &p, nil
}

// Split splits a policy into multiple policies with a size limit.
func Split(policy *awspolicy.Policy, limit int) []*awspolicy.Policy {
	if jsonSize(policy) < limit {
		return []*awspolicy.Policy{policy}
	}

	var policies []*awspolicy.Policy
	tmp := &awspolicy.Policy{
		Version:    policy.Version,
		Statements: []awspolicy.Statement{},
	}
	for _, statement := range policy.Statements {
		if jsonSize(tmp)+jsonSize(statement) > limit {
			if len(tmp.Statements) > 0 { // Ensure tmp is not empty before appending
				policies = append(policies, tmp)
			}
			tmp = &awspolicy.Policy{
				Version:    policy.Version,
				Statements: []awspolicy.Statement{},
			}
		}
		tmp.Statements = append(tmp.Statements, statement)
	}
	if len(tmp.Statements) > 0 { // Append the last batch of statements if not empty
		policies = append(policies, tmp)
	}
	return policies
}


// Merge merges multiple policies into a single policy.
func Merge(name string, version string, policies []*Policy) *Policy {
	result := &Policy{
		Version:    version,
		ID:         name,
		Statements: []Statement{},
	}
	for _, policy := range policies {
		result.Statements = append(result.Statements, policy.Statements...)
	}
	return result
}

func jsonSize(p any) int {
	b, _ := json.Marshal(p)
	return len(b)
}
