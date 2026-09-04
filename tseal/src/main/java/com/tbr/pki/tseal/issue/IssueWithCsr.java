package com.tbr.pki.tseal.issue;

import com.tbr.pki.tseal.policy.IssuancePolicy;

public interface IssueWithCsr {
    IssueWithPolicy policy(IssuancePolicy policy);
}
