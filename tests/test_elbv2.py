from conftest import REGION

from aws_audit.checks.elbv2 import http_not_redirected


def _alb(aws, name):
    ec2 = aws.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnets = [
        ec2.create_subnet(VpcId=vpc, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=f"{REGION}{az}")[
            "Subnet"
        ]["SubnetId"]
        for i, az in enumerate("ab")
    ]
    elb = aws.client("elbv2", region_name=REGION)
    lb = elb.create_load_balancer(Name=name, Subnets=subnets)["LoadBalancers"][0]
    tg = elb.create_target_group(Name=f"{name}-tg", Protocol="HTTP", Port=80, VpcId=vpc)
    return elb, lb["LoadBalancerArn"], tg["TargetGroups"][0]["TargetGroupArn"]


def test_http_forward_is_flagged_redirect_is_not(aws):
    elb, lb, tg = _alb(aws, "shop")
    elb.create_listener(
        LoadBalancerArn=lb,
        Protocol="HTTP",
        Port=8080,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}],
    )
    elb.create_listener(
        LoadBalancerArn=lb,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[
            {
                "Type": "redirect",
                "RedirectConfig": {"Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301"},
            }
        ],
    )

    issues = list(http_not_redirected(aws, REGION))

    assert [i.resource for i in issues] == ["shop:8080"]


def test_no_load_balancers(aws):
    assert list(http_not_redirected(aws, REGION)) == []
