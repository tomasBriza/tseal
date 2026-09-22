package io.github.tomasbriza.tseal.issue;

import io.github.tomasbriza.tseal.policy.IssuancePolicy;

public interface IssueWithCsr {
    IssueWithPolicy policy(IssuancePolicy policy);
}
