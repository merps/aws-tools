#!/usr/bin/env python
#
# Python Version: 2.7
# boto Version 2.38 / boto3 version 1.2.3
#
# Create a VPC
#

# Must be the first line
from __future__ import print_function

# https://pythonhosted.org/netaddr
from netaddr import *

import sys
import json
import boto.vpc
import boto.ec2
from boto3.session import Session


class Tag():
    def __init__(self, name, resource, region):
        abbr = '-nul'
        if region == 'us-east-1':      abbr = '-ue1'
        if region == 'eu-west-1':      abbr = '-ew1'
        if region == 'ap-northeast-1': abbr = '-an1'
        if region == 'us-west-1':      abbr = '-uw1'
        if region == 'us-west-2':      abbr = '-uw2'
        if region == 'ap-southeast-1': abbr = '-as1'
        if region == 'ap-southeast-2': abbr = '-as2'
        if region == 'eu-central-1':   abbr = '-ec1'
        if region == 'sa-east-1':      abbr = '-se1'

        self.name = name + resource + abbr

    def tag_resource(self, conn, resource_id):
        conn.create_tags(resource_id, {'Name': self.name})


class Template:
    RolePolicy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': '',
                'Effect': 'Allow',
                'Principal': {
                    'Service': 'vpc-flow-logs.amazonaws.com'
                },
                'Action': 'sts:AssumeRole'
            }
        ]
    }

    LogsPolicy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Action': [
                    'logs:CreateLogGroup',
                    'logs:CreateLogStream',
                    'logs:DescribeLogGroups',
                    'logs:DescribeLogStreams',
                    'logs:PutLogEvents'
                ],
                'Effect': 'Allow',
                'Resource': '*'
            }
        ]
    }


def create_vpc(conn, name, region, cidr):
    """ Create the VPC """

    try:
        vpc = conn.create_vpc(cidr, instance_tenancy='default')
    except boto.exception.EC2ResponseError as e:
        print(e.message)
        exit(1)
    else:
        conn.modify_vpc_attribute(vpc.id, enable_dns_support=True)
        conn.modify_vpc_attribute(vpc.id, enable_dns_hostnames=True)
        t = Tag(name, 'vpc', region);
        t.tag_resource(conn, vpc.id)

        print("vpc-id: ", vpc.id, "\tname: ", t.name)
        return vpc.id


def create_igw(conn, name, region, vpc_id):
    """ Create and attach an igw """

    try:
        igw = conn.create_internet_gateway()
    except boto.exception.EC2ResponseError as e:
        print(e.message)
        exit(1)
    else:
        conn.attach_internet_gateway(igw.id, vpc_id)
        t = Tag(name, 'igw', region);
        t.tag_resource(conn, igw.id)

        return igw.id


def subnet_sizes(azs, cidr):
    """
    Calculate subnets sizes

    Possible scenarios:
      a) /25 2AZ  (4 Subnets = /27)
      b) /24 2AZ  (4 Subnets = /26)
      c) /23 2AZ  (4 Subnets = /25)
      d) /22 2AZ  (4 Subnets = /24)
      e) /23 3AZ  (3 Subnets = /27, 3 Subnets = /25)
      f) /22 3AZ  (3 Subnets = /26, 3 Subnets = /24)
    """

    if azs != 2 and azs != 3:
        print("ERROR: Number of AZs should be 2 or 3.")
        exit(1)

    netmasks = ('255.255.252.0', '255.255.254.0', '255.255.255.0', '255.255.255.128')

    ip = IPNetwork(cidr)
    mask = ip.netmask

    if azs == 3:
        if str(mask) not in netmasks[0:2]:
            print("ERROR: Netmask " + str(mask) + " not found.")
            exit(1)

        for n, netmask in enumerate(netmasks):
            if str(mask) == netmask:
                pub_net = list(ip.subnet(n + 24))
                pri_subs = pub_net[1:]
                pub_mask = pub_net[0].netmask

        pub_split = list(ip.subnet(26)) if (str(pub_mask) == '255.255.255.0') else list(ip.subnet(27))
        pub_subs = pub_split[:3]

        subnets = pub_subs + pri_subs

    else:
        if str(mask) not in netmasks:
            print("ERROR: Netmask " + str(mask) + " not found.")
            exit(1)

        for n, netmask in enumerate(netmasks):
            if str(mask) == netmask:
                subnets = list(ip.subnet(n + 24))
    return subnets


def create_sub(conn, name, region, vpc_id, azs, subnets, zones):
    """ Create subnets """

    i = 0;
    sub_ids = [];
    tier = 'public'
    for sub in subnets:
        subnet = conn.create_subnet(vpc_id, sub, availability_zone=zones[i])
        t = Tag(name, tier + '-sub', region);
        t.tag_resource(conn, subnet.id)

        sub_ids.append(subnet.id)
        print("sub-id: ", subnet.id, "\tsize: ", sub, "\tzone: ", zones[i])
        i += 1
        if i == azs: i = 0; tier = 'private'

    return sub_ids


def create_rtb(conn, name, region, vpc_id, azs, sub_ids, igw_id):
    """ Create and associate route-tables """

    i = 0;
    rtb_ids = [];
    tier = 'public'
    for sub in sub_ids:
        if i == 0:
            rtb = conn.create_route_table(vpc_id)
            conn.create_route(rtb.id, '0.0.0.0/0', igw_id)
            t = Tag(name, tier + '-rtb', region);
            t.tag_resource(conn, rtb.id)

            rtb_ids.append(rtb.id)
        conn.associate_route_table(rtb.id, sub)
        i += 1
        if i == azs: i = 0; tier = 'private'

    return rtb_ids


def create_acl(conn, name, region, vpc_id, azs, sub_ids, cidr):
    """ Create and associate network access-lists

        https://blogs.aws.amazon.com/security/post/Tx3NVS2JAL7KWOM/How-to-Help-Prepare-for-DDoS-Attacks-by-Reducing-Your-Attack-Surface
    """

    i = 0;
    acl_ids = [];
    tier = 'public'
    for sub in sub_ids:
        if i == 0:
            acl = conn.create_network_acl(vpc_id)
            conn.create_network_acl_entry(acl.id, 100, -1, 'allow', cidr, egress=False)
            conn.create_network_acl_entry(acl.id, 200, 6, 'allow', '0.0.0.0/0', egress=False, port_range_from=443,
                                          port_range_to=443)
            conn.create_network_acl_entry(acl.id, 300, 6, 'allow', '0.0.0.0/0', egress=False, port_range_from=80,
                                          port_range_to=80)
            conn.create_network_acl_entry(acl.id, 400, 6, 'allow', '0.0.0.0/0', egress=False, port_range_from=1024,
                                          port_range_to=65535)
            conn.create_network_acl_entry(acl.id, 500, 6, 'allow', '0.0.0.0/0', egress=False, port_range_from=22,
                                          port_range_to=22)
            conn.create_network_acl_entry(acl.id, 100, -1, 'allow', cidr, egress=True)
            conn.create_network_acl_entry(acl.id, 200, 6, 'allow', '0.0.0.0/0', egress=True, port_range_from=443,
                                          port_range_to=443)
            conn.create_network_acl_entry(acl.id, 300, 6, 'allow', '0.0.0.0/0', egress=True, port_range_from=80,
                                          port_range_to=80)
            conn.create_network_acl_entry(acl.id, 400, 6, 'allow', '0.0.0.0/0', egress=True, port_range_from=1024,
                                          port_range_to=65535)
            conn.create_network_acl_entry(acl.id, 500, 6, 'allow', '0.0.0.0/0', egress=True, port_range_from=22,
                                          port_range_to=22)
            t = Tag(name, tier + '-acl', region);
            t.tag_resource(conn, acl.id)

            acl_ids.append(acl.id)
        conn.associate_network_acl(acl.id, sub)
        i += 1
        if i == azs: i = 0; tier = 'private'

    return acl_ids


def create_flows(vpc_id, keyid, secret, region):
    """ Create VPC flow logs """

    session = Session(aws_access_key_id=keyid, aws_secret_access_key=secret, region_name=region)

    iam = session.client('iam')
    logs = session.client('logs')
    ec2 = session.client('ec2')

    # Check for an existing Role with standard name
    try:
        role = iam.get_role(RoleName='flowlogsRole')
    except:
        role = 'None'

    # Create VPC Flows Logs IAM Role
    if role != 'None':
        role_arn = role['Role']['Arn']
        error = 'None'
    else:
        try:
            role = iam.create_role(
                Path='/',
                RoleName='flowlogsRole',
                AssumeRolePolicyDocument=json.dumps(Template.RolePolicy))
        except Exception as e:
            error = e.message;
            print(error)
            flow_id = 'null'
        else:
            error = 'None'

            # Create VPC Flow Logs policy
            policy = iam.create_policy(
                Path='/',
                PolicyName='flowlogsPolicy',
                Description='Grants access to CloudWatch Logs.',
                PolicyDocument=json.dumps(Template.LogsPolicy))

            role_name = role['Role']['RoleName']
            role_arn = role['Role']['Arn']
            policy_arn = policy['Policy']['Arn']

            # Attach policy to the IAM Role
            attach = iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn)

    if error == 'None':
        logs_name = 'flowlogsGroup' + '-' + vpc_id

        # Create CloudWatch Logs group
        group = logs.create_log_group(logGroupName=logs_name)
        retention = logs.put_retention_policy(logGroupName=logs_name, retentionInDays=14)

        # Enable VPC Flow Logs
        flow_id = ec2.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType='VPC',
            TrafficType='ALL',
            LogGroupName=logs_name,
            DeliverLogsPermissionArn=role_arn)

    return flow_id


def main(azs, region, keyid, secret, cidr, owner, env):
    """
    Do the work

    1.) Setup/validate region and availability-zones
    2.) Create the VPC
    3.) Create and attach an internet-gateway
    4.) Calculate subnet sizes (netaddr)
    5.) Create subnets
    6.) Create and associate route-tables
    7.) Create and associate network access-lists
    8.) Enable VPC Flow Logs
    """

    # Validate the region
    myregion = boto.ec2.get_region(region_name=region)
    if myregion == None:
        print("Unknown region.")
        exit(1)

    # Establish a VPC service connection
    try:
        conn = boto.vpc.VPCConnection(aws_access_key_id=keyid, aws_secret_access_key=secret, region=myregion)
    except boto.exception.EC2ResponseError as e:
        print(e.message)
        exit(1)

    # Grab the availability-zones
    zones = []
    all_zones = conn.get_all_zones()
    for zone in all_zones:
        if zone.state != 'available':
            continue
        zones.append(zone.name)

    subnets = subnet_sizes(azs, cidr)  # Calculate the subnet sizes
    name = owner.lower() + '-' + env.lower() + '-'  # Used for tagging

    vpc_id = create_vpc(conn, name, region, cidr)
    igw_id = create_igw(conn, name, region, vpc_id)
    sub_ids = create_sub(conn, name, region, vpc_id, azs, subnets, zones)
    rtb_ids = create_rtb(conn, name, region, vpc_id, azs, sub_ids, igw_id)
    acl_ids = create_acl(conn, name, region, vpc_id, azs, sub_ids, cidr)
    flow_id = create_flows(vpc_id, keyid, secret, region)


if __name__ == "__main__":
    main(azs=3, region='ap-southeast-2', keyid='AKIAIOQJDVBKPWRBTZ4Q', secret='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', cidr='10.64.0.0/22', owner='merps', env='tst')