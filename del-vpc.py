#!/usr/bin/env python3
import boto3
import json
import botocore
import argparse
import sys
from netaddr import *

class Interaction(object):
    def __init__(self):
        parser = argparse.ArgumentParser(
            description='AWS CrossAccount Environment creation',
            usage='''aws-vpc <command> [<args>]

    There is two ways to execute this script:
        create      To create a Tiered AWS Environment
        delete      To delete the VPC and all associated resources/elements
        ''')
        parser.add_argument('command', help='Parameters to pass for Environment Creation')
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print('Unrecognised command')
            parser.print_help()
            exit(1)
        getattr(self, args.command)()

    def create(self):
        parser = argparse.ArgumentParser(
            description='To create the AWS Tiered network Environment'
        )
        parser.add_argument('--name', type=str, required=False,
                            help='the customer code/reference to be used for creation.')
        parser.add_argument('--acct', type=str, required=True,
                            help='AWS Customer account number for environment location')
        parser.add_argument('--role', type=str, required=True,
                            help='AWS IAM Role within the account')
        parser.add_argument('--cidr', type=str, required=True,
                            help='CIDR Range for VPC')
        parser.add_argument('--region', type=str, required=True,
                            help='region to create aws environment')
        parser.add_argument('--tiers', type=str, required=True,
                            help='Tiers required for deployment')
        parser.add_argument('--tags', type=str, required=False,
                            help='the tags to attach to the stack.')
        args = parser.parse_args(sys.argv[2:])
        return args


class AWSTagging(object):
    # TODO - this bloody tagging thing - resources are different to clients.
    def __init__(self):
        self.name = name
        return name

class AWSSession(object):
    def __init__(self, arn, region, role_session_name):
        self.arn = arn
        self.region = region
        self.role_session_name = role_session_name
        self._token = None
        self._ec2 = None
        self._aws_access_key_id = None
        self._aws_secret_access_key = None
        self._aws_session_token = None

    @property
    def token(self):
        return self._token or self.role_arn_to_session()

    @property
    def ec2(self):
        return self._ec2 or self.connect_to_ec2()

    def role_arn_to_session(self):
        client = boto3.client('sts')
        response = client.assume_role(RoleArn=self.arn, RoleSessionName=self.role_session_name)
        self._aws_access_key_id = response['Credentials']['AccessKeyId'],
        self._aws_secret_access_key = response['Credentials']['SecretAccessKey'],
        self._aws_session_token = response['Credentials']['SessionToken'],
        self._token = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'],
            region_name=self.region
        )
        return self._token

    def connect_to_ec2(self):
        self._ec2 = boto3.client('ec2',
                                 aws_access_key_id=self._aws_access_key_id[0],
                                 aws_secret_access_key=self._aws_secret_access_key[0],
                                 aws_session_token=self._aws_session_token[0],
                                 region_name=self.region
                                 )
        return self._ec2

    def connect_to_resource(selfself):
        resource = boto3.resource('ec2')


class AWSNetworking(object):
    def vpc_creation(self, session, cidr):
        # TODO tag the resource also.
        vpc_resp = session.ec2.create_vpc(
            DryRun=False,
            CidrBlock=cidr,
            InstanceTenancy='default',
        )
        vpc_id = vpc_resp['Vpc']['VpcId']
        print("Created VPC: {0}".format(vpc_id))
        session.ec2.get_waiter('vpc_available').wait(VpcIds=[vpc_id])
        # session.ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={'Value': True})
        # session.ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={'Value': True})
        # create_tags(vpc_id, vpc_name_tag, ec2c, deployed_environment)
        print("VPC: {0} is now available. Continuing".format(vpc_id))
        return vpc_id

    def delete_igw(self, session, vpc_id):
        # TODO tag this resource

        igw = session.ec2.create_internet_gateway()
        igw_id = igw['InternetGateway']['InternetGatewayId']
        print("Created IGW: {0}".format(igw_id))
        response = session.ec2.attach_internet_gateway(
            DryRun = False,
            InternetGatewayId=igw_id,
            VpcId=vpc_id
        )
        # TODO so pull the 200OK out of this and give an all clear or a waiter?
        # print(response)
        return igw_id

    def create_subnets(self, session, vpc_id, zones, subnets):
        # TODO is there waiters that can be used here, tagging elements here also.
        i = 0; sub_ids = []; tier = 'public'; azs = len(zones)
        for sub in subnets:
            subnet = session.ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=str(subnets[i]),
                AvailabilityZone=zones[i])
            sub_ids.append(subnet['Subnet']['SubnetId'])
            print("sub-id: ", subnet['Subnet']['SubnetId'], "\tsize: ", sub, "\tzone: ", zones[i])
            i += 1
            if i == azs:
                subnets = subnets[azs:]
                i = 0
        return sub_ids

    def create_routes(self, session, vpc_id, zones, igw_id, sub_ids):
        # TODO check if there is waiters for RTB's, tagging also here.
        i = 0
        rtb_ids = []
        azs = len(zones)
        for sub in sub_ids:
            if i == 0:
                rtb = session.ec2.create_route_table(
                    VpcId=vpc_id
                )
                rtb_id = rtb['RouteTable']['RouteTableId']
                response = session.ec2.create_route(
                    RouteTableId=rtb_id,
                    DestinationCidrBlock='0.0.0.0/0',
                    GatewayId=igw_id,
                )
                rtb_ids.append(rtb_id)
            response = session.ec2.associate_route_table(
                SubnetId = sub,
                RouteTableId = rtb_id
            )
            i += 1
            if i == azs:
                i = 0
                tier = 'private'
        return rtb_ids

    def create_acl(self, session, zones, vpc_id, sub_ids, cidr):
        # TODO need to resource tag and create tiers (app, web, db, dmz, etc)
        i = 0
        azs = len(zones)
        acl_ids = []
        associations = []
        tier = 'public'
        acl = session.ec2.create_network_acl(
            VpcId=vpc_id
        )
        acl_id = acl['NetworkAcl']['NetworkAclId']
        for sub in sub_ids:
            if i == 0:
                session.ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=100, Protocol='-1', RuleAction='allow',
                                                     CidrBlock=cidr, Egress=False)
                session.ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=200, Protocol='6', RuleAction='allow',
                                                     CidrBlock='0.0.0.0/0', Egress=False, PortRange={'From': 22,
                                                     'To': 22})
                session.ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=300, Protocol='6', RuleAction='allow',
                                                     CidrBlock='0.0.0.0/0', Egress=False, PortRange={'From': 80,
                                                     'To': 80})
                session.ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=400, Protocol='6', RuleAction='allow',
                                                     CidrBlock='0.0.0.0/0', Egress=False, PortRange={'From': 443,
                                                     'To': 443})
                session.ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=500, Protocol='6', RuleAction='allow',
                                                     CidrBlock='0.0.0.0/0', Egress=False, PortRange={'From': 1024,
                                                     'To': 65535})
                session.ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=100, Protocol='-1', RuleAction='allow',
                                                     CidrBlock=cidr, Egress=True)
                session.ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=200, Protocol='6', RuleAction='allow',
                                                     CidrBlock='0.0.0.0/0', Egress=True, PortRange={'From': 22,
                                                     'To': 22})
                session.ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=300, Protocol='6', RuleAction='allow',
                                                     CidrBlock='0.0.0.0/0', Egress=True, PortRange={'From': 80,
                                                     'To': 80})
                session.ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=400, Protocol='6', RuleAction='allow',
                                                     CidrBlock='0.0.0.0/0', Egress=True, PortRange={'From': 443,
                                                     'To': 443})
                session.ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=500, Protocol='6', RuleAction='allow',
                                                     CidrBlock='0.0.0.0/0', Egress=True, PortRange={'From': 1024,
                                                     'To': 65535})
                response = session.ec2.describe_network_acls(
                    Filters=[{
                        'Name': 'vpc-id',
                        'Values': [
                            vpc_id
                        ]
                    }])
            i += 1
            if i == azs:
                i = 0
                tier = 'private'
        response = session.ec2.describe_network_acls(NetworkAclIds=[], Filters=[])

        for acl in response['NetworkAcls']:
            if (acl["VpcId"] == vpc_id and len(acl['Associations']) > 0):
                associations = acl['Associations']

        for a in associations:
            session.ec2.replace_network_acl_association(
                AssociationId=a['NetworkAclAssociationId'],
                NetworkAclId=acl_id
            )
        return acl_ids


def main(cidr, arn, region, tiers):
    # TODO would the output be better as JSON?
    session = AWSSession(
        arn=arn,
        region=region,
        role_session_name='vpc_sts'
    )
    session.role_arn_to_session()
    networks = AWSNetworking()

    return 0


if __name__ == "__main__":
    request = Interaction()
    response = request.create()
    # TODO query for parameters/arguments
    main(cidr=response.cidr, arn='arn:aws:iam::{}:role/{}'.format(response.acct, response.role), region=response.region,
         tiers=response.tiers)