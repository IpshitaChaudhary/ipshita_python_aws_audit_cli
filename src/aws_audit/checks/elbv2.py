"""Application Load Balancer checks."""

from __future__ import annotations

from collections.abc import Iterator

import boto3

from aws_audit.models import Issue, Severity
from aws_audit.registry import check


def _is_https_redirect(action: dict) -> bool:
    return action.get("Type") == "redirect" and (
        action.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
    )


@check("elbv2.http-not-redirected", "ALB HTTP listeners redirect to HTTPS", Severity.MEDIUM)
def http_not_redirected(session: boto3.Session, region: str) -> Iterator[Issue]:
    """An HTTP listener should only redirect; anything else serves traffic unencrypted.

    Only the default action is checked: a listener whose default is a redirect
    but whose rules forward some paths over HTTP is not caught.
    """
    elb = session.client("elbv2", region_name=region)
    for page in elb.get_paginator("describe_load_balancers").paginate():
        for lb in page["LoadBalancers"]:
            if lb.get("Type") != "application":
                continue
            listeners = elb.describe_listeners(LoadBalancerArn=lb["LoadBalancerArn"])
            for listener in listeners["Listeners"]:
                if listener["Protocol"] != "HTTP":
                    continue
                if not any(_is_https_redirect(a) for a in listener["DefaultActions"]):
                    yield Issue(
                        f"{lb['LoadBalancerName']}:{listener['Port']}",
                        f"HTTP listener on port {listener['Port']} serves traffic instead of "
                        "redirecting to HTTPS",
                    )
