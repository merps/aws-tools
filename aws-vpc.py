#!/usr/bin/env python3
import boto3
import json
from botocore.exceptions import ClientError, ParamValidationError
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
        delete      To delete the VPC and all associated resources/elements (TO BE DONE - not functioning, yet)
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
        parser.add_argument('--mfa', type=str, required=True,
                            help='AWS account number for MFA Token')
        parser.add_argument('--user', type=str, required=True,
                            help='AWS username for MFA Token')
        parser.add_argument('--region', type=str, required=True,
                            help='region to create aws environment')
        parser.add_argument('--tiers', type=str, required=True,
                            help='Tiers required for deployment')
        parser.add_argument('--env', type=str, required=True,
                            help='Environment classification for deployment')
        parser.add_argument('--project', type=str, required=True,
                            help='Project designation for deployment')
        parser.add_argument('--tags', type=str, required=False,
                            help='the tags to attach to the stack.')
        args = parser.parse_args(sys.argv[2:])
        return args

    def delete(self):
        parser = argparse.ArgumentParser(
            description='delete the complete solution'
        )
        parser.add_argument('--vpcid', type=str, required=True,
                            help='the name of the stack to delete.')
        parser.add_argument('--retain', type=str, required=False,
                            help='the names (comma separated) of the resources to retain.')
        parser.add_argument('--log', type=str, default="INFO", required=False,
                            help='which log level. DEBUG, INFO, WARNING, CRITICAL')
        parser.add_argument('--config', type=str, required=False,
                            help='the config file used for the application.')
        args = parser.parse_args(sys.argv[2:])
        print("running args %s" % args)
        return args


class Tag(object):

  def __init__(self, resource, name, env):
    self.name = resource + '_' + name + '_' + env

  def tag_resource(self, session, resource):
      session.ec2c.create_tags(Resources=[resource], Tags=[{'Key': 'Name', 'Value': self.name}])


class AWSResources(object):
    def __init__(self):
        self.key = key
        self.value = value
        self._tags = None

    @property
    def tags(self):
        return self._tags


class AWSSession(object):
    def __init__(self, arn, region, role_session_name, mfa_serial, mfa_TOTP):
        self.arn = arn
        self.region = region
        self.role_session_name = role_session_name
        self.mfa_serial = mfa_serial
        self.mfa_TOTP = mfa_TOTP
        # TODO is to validate profile passing
        # self.role_session_profile = role_session_profile
        # self.temp_creds = temp_generated_creds
        self._token = None
        self._ec2c = None
        self._ec2r = None
        self._aws_access_key_id = None
        self._aws_secret_access_key = None
        self._aws_session_token = None

    @property
    def ec2c(self):
        return self._ec2c or self.connect_to_ec2c()

    @property
    def ec2r(self):
        return self._ec2r or self.resource_of_ec2r()

    def role_arn_to_session(self):
        client = boto3.client('sts')
        response = client.assume_role(
            RoleArn=self.arn,
            RoleSessionName=self.role_session_name,
            DurationSeconds=900,
            SerialNumber=self.mfa_serial,
            TokenCode=self.mfa_TOTP
        )
        self._aws_access_key_id = response['Credentials']['AccessKeyId'],
        self._aws_secret_access_key = response['Credentials']['SecretAccessKey'],
        self._aws_session_token = response['Credentials']['SessionToken'],
        self._token = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'],
            # TODO is to validate the requirement for profile (~/.aws/config or creds) sourcing
            # profile_name=self.role_session_profile,
            region_name=self.region
        )
        return self._token

    def connect_to_ec2c(self):
        self._ec2c = boto3.client('ec2',
                                 aws_access_key_id=self._aws_access_key_id[0],
                                 aws_secret_access_key=self._aws_secret_access_key[0],
                                 aws_session_token=self._aws_session_token[0],
                                 )
        return self._ec2c

    def resource_of_ec2r(self):
        self._ec2r = boto3.resource('ec2',
                                 aws_access_key_id=self._aws_access_key_id[0],
                                 aws_secret_access_key=self._aws_secret_access_key[0],
                                 aws_session_token=self._aws_session_token[0],
                                 )
        return self._ec2r


class AWSNetworking(object):
    def zone_availability(self, session):
        # TODO fix this so we can make it worldwide.
        availZones = []
        for zone in session.ec2c.describe_availability_zones()['AvailabilityZones']:
            if zone['State'] != 'available':
                continue
            availZones.append(zone['ZoneName'])
        return availZones

    def subnet_size(self, zones, cidr, tiers):
        # TODO need to clean the calculations and also look at passing CIDR's for customisation?
        azs = len(zones)
        # TODO removed for us-east-1 (six bloody AZ's), need additional testing here.
        if azs != 2 and azs != 3:
            print("ERROR: Number of AZs should be 2 or 3.")
            exit(1)

        # TODO address /<cidr> size of reduced tiers or smaller cidr mask bit
        netmasks = ('255.255.248.0', '255.255.252.0', '255.255.254.0', '255.255.255.0', '255.255.255.128')

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

            # TODO - removal for enboarder, this was to address the 6 AZ's
            # pub_split = list(ip.subnet(24)) if (str(pub_mask) == '255.255.255.0') else list(ip.subnet(27))
            # pub_subs = pub_split[:2]

            subnets = pub_subs + pri_subs
            layers = int(tiers) * azs
            subnets = subnets[:layers]
        # TODO Fix for 6 AZ's - this is a BAD hack!!!
        elif azs == 6:
            if str(mask) not in netmasks[0:4]:
                print("ERROR: Netmask " + str(mask) + " not found.")
                exit(1)

            for n, netmask in enumerate(netmasks):
                if str(mask) == netmask:
                    pub_net = list(ip.subnet(n + 21))
                    pri_subs = pub_net[5:]
                    pub_mask = pub_net[0].netmask

            pub_split = list(ip.subnet(28)) if (str(pub_mask) == '255.255.255.0') else list(ip.subnet(28))
            pub_subs = pub_split[:6]
            subnets = pub_subs + pri_subs
            layers = int(tiers) * azs
            subnets = subnets[:layers]

        else:
            if str(mask) not in netmasks:
                print("ERROR: Netmask " + str(mask) + " not found.")
                exit(1)

            for n, netmask in enumerate(netmasks):
                if str(mask) == netmask:
                    subnets = list(ip.subnet(n + 24))
        return subnets

    def vpc_creation(self, session, cidr, env, project):
        # TODO tag the resource also, first attempt at exception handling - needs better?
        try:
            vpc_resp = session.ec2c.create_vpc(
                DryRun=False,
                CidrBlock=cidr,
                InstanceTenancy='default',
            )
            vpc_id = vpc_resp['Vpc']['VpcId']
            print("Created VPC: {0}".format(vpc_id))
            session.ec2c.get_waiter('vpc_available').wait(VpcIds=[vpc_id])
            session.ec2c.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={'Value': True})
            session.ec2c.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={'Value': True})
            t = Tag('vpc', project, env)
            t.tag_resource(session, vpc_id)
            print("VPC: {0} is now available. Continuing".format(vpc_id))
            return vpc_id
        except ClientError as e:
            print(e.response['Error']['Message'], 'Cannot continue until VPC limit is adjusted.')
            sys.exit(1)

    def create_igw(self, session, vpc_id, env, project):
        # TODO tag this resource, better Exception Handling needed here.
        try:
            igw = session.ec2c.create_internet_gateway()
            igw_id = igw['InternetGateway']['InternetGatewayId']
            t = Tag('igw', project, env)
            t.tag_resource(session, igw_id)
            print("Created IGW: {0}".format(igw_id))
            response = session.ec2c.attach_internet_gateway(
                DryRun = False,
                InternetGatewayId=igw_id,
                VpcId=vpc_id
            )
            # TODO so pull the 200OK out of this and give an all clear or a waiter?
            return igw_id
        except ClientError as e:
            print(e.response['Error']['Message'])
            sys.exit(1)

    def create_subnets(self, session, vpc_id, zones, subnets, env, project):
        # TODO is there waiters that can be used here, tagging elements here also. Exception Handling needed here.
        try:
            i = 0; sub_ids = []; tier = 'public'; azs = len(zones)
            for sub in subnets:
                subnet = session.ec2c.create_subnet(
                    VpcId=vpc_id,
                    CidrBlock=str(subnets[i]),
                    AvailabilityZone=zones[i])
                t = Tag('subnet', project, env)
                t.tag_resource(session, subnet['Subnet']['SubnetId'])
                sub_ids.append(subnet['Subnet']['SubnetId'])
                print("sub-id: ", subnet['Subnet']['SubnetId'], "\tsize: ", sub, "\tzone: ", zones[i])
                i += 1
                if i == azs:
                    subnets = subnets[azs:]
                    i = 0
            return sub_ids
        except ParamValidationError as e:
            print(e)
            sys.exit(1)

    def create_routes(self, session, vpc_id, zones, igw_id, sub_ids, env, project):
        # TODO check if there is waiters for RTB's, tagging also here. Exception Handling needed here.
        i = 0
        rtb_ids = []
        azs = len(zones)
        for sub in sub_ids:
            if i == 0:
                rtb = session.ec2c.create_route_table(
                    VpcId=vpc_id
                )
                rtb_id = rtb['RouteTable']['RouteTableId']
                t = Tag('rt', project, env)
                t.tag_resource(session, rtb_id)
                print("Created Route Table: {0}".format(rtb_id))
                response = session.ec2c.create_route(
                    RouteTableId=rtb_id,
                    DestinationCidrBlock='0.0.0.0/0',
                    GatewayId=igw_id,
                )
                rtb_ids.append(rtb_id)
            response = session.ec2c.associate_route_table(
                SubnetId = sub,
                RouteTableId = rtb_id
            )
            print("Associated rtb-id: {0} \twith sub-id: {1}".format(rtb_id, sub))
            i += 1
            if i == azs:
                i = 0
                tier = 'private'
        return rtb_ids

    def create_acl(self, session, zones, vpc_id, sub_ids, cidr, env, project):
        # TODO need to resource tag and create tiers (app, web, db, dmz, etc), Exception Handling needed here.
        i = 0
        azs = len(zones)
        acl_ids = []
        associations = []
        tier = 'public'
        acl = session.ec2c.create_network_acl(
            VpcId=vpc_id
        )
        acl_id = acl['NetworkAcl']['NetworkAclId']
        t = Tag('nacl', project, env)
        t.tag_resource(session, acl_id)
        print("Created Network ACL: {0}".format(acl_id))
        for sub in sub_ids:
            if i == 0:
                session.ec2c.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=100, Protocol='-1',
                                                      RuleAction='allow', CidrBlock=cidr, Egress=False)
                session.ec2c.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=200, Protocol='6',
                                                      RuleAction='allow', CidrBlock='0.0.0.0/0', Egress=False,
                                                      PortRange={'From': 22, 'To': 22})
                session.ec2c.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=300, Protocol='6',
                                                      RuleAction='allow',  CidrBlock='0.0.0.0/0', Egress=False,
                                                      PortRange={'From': 80, 'To': 80})
                session.ec2c.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=400, Protocol='6',
                                                      RuleAction='allow', CidrBlock='0.0.0.0/0', Egress=False,
                                                      PortRange={'From': 443, 'To': 443})
                session.ec2c.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=500, Protocol='6',
                                                      RuleAction='allow', CidrBlock='0.0.0.0/0', Egress=False,
                                                      PortRange={'From': 1024, 'To': 65535})
                session.ec2c.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=100, Protocol='-1',
                                                      RuleAction='allow', CidrBlock=cidr, Egress=True)
                session.ec2c.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=200, Protocol='6',
                                                      RuleAction='allow', CidrBlock='0.0.0.0/0', Egress=True,
                                                      PortRange={'From': 22, 'To': 22})
                session.ec2c.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=300, Protocol='6',
                                                      RuleAction='allow', CidrBlock='0.0.0.0/0', Egress=True,
                                                      PortRange={'From': 80, 'To': 80})
                session.ec2c.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=400, Protocol='6',
                                                      RuleAction='allow', CidrBlock='0.0.0.0/0', Egress=True,
                                                      PortRange={'From': 443, 'To': 443})
                session.ec2c.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=500, Protocol='6',
                                                      RuleAction='allow', CidrBlock='0.0.0.0/0', Egress=True,
                                                      PortRange={'From': 1024, 'To': 65535})
                response = session.ec2c.describe_network_acls(
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
        response = session.ec2c.describe_network_acls(NetworkAclIds=[], Filters=[])

        for acl in response['NetworkAcls']:
            if (acl["VpcId"] == vpc_id and len(acl['Associations']) > 0):
                associations = acl['Associations']

        for a in associations:
            session.ec2c.replace_network_acl_association(
                AssociationId=a['NetworkAclAssociationId'],
                NetworkAclId=acl_id
            )
            # print("acl-id: ", acl_id, "\tassociated with vpc-id: ", sub, "\tzone: ", zones[i])
        return acl_ids


def main(cidr, arn, mfa_arn, region, tiers, env, project):
    # TODO would the output be better as JSON? Exception Handling needed here.
    mfa_TOTP = input("Enter MFA Token Code: ")
    session = AWSSession(
        arn=arn,
        role_session_name='vpc_sts',
        region=region,
        mfa_serial=mfa_arn,
        mfa_TOTP=mfa_TOTP
    )
    session.role_arn_to_session()
    networks = AWSNetworking()

    zones = networks.zone_availability(session)
    vpc_id = networks.vpc_creation(session, cidr, env, project)
    igw_id = networks.create_igw(session, vpc_id, env, project)
    subnets = networks.subnet_size(zones, cidr, tiers)
    sub_ids = networks.create_subnets(session, vpc_id, zones, subnets, env, project)
    rtb_ids = networks.create_routes(session, vpc_id, zones, igw_id, sub_ids, env, project)
    acl_ids = networks.create_acl(session, zones, vpc_id, sub_ids, cidr, env, project)
    return 0


if __name__ == "__main__":
    request = Interaction()
    response = request.create()
    # TODO query for parameters/arguments, better Exception Handling needed here.
    main(cidr=response.cidr, arn='arn:aws:iam::{}:role/{}'.format(response.acct, response.role),
         mfa_arn='arn:aws:iam::{}:mfa/{}'.format(response.mfa, response.user), region=response.region,
         tiers=response.tiers, env=response.env, project=response.project)