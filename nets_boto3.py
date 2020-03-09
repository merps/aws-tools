#!/usr/bin/env python3
import boto3
import json
import botocore
from netaddr import *


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
            region_name=self.region,
        )
        return self._token

    def connect_to_ec2(self):
        self._ec2 = boto3.client('ec2',
                                 aws_access_key_id=self._aws_access_key_id[0],
                                 aws_secret_access_key=self._aws_secret_access_key[0],
                                 aws_session_token=self._aws_session_token[0],
                                 )
        return self._ec2


class AWSNetworking(object):

    def zone_availability(self, session):
        availZones = []
        for zone in session.ec2.describe_availability_zones()['AvailabilityZones']:
            if zone['State'] == 'available':
                availZones.append(zone['ZoneName'])
        return availZones

    def subnet_size(self, zones, cidr):
        azs = len(zones)
        if azs != 2 and azs != 3:
            print("ERROR: Number of AZs should be 2 or 3.")
            exit(1)

        netmasks = ('255.255.240.0', '255.255.252.0', '255.255.254.0', '255.255.255.0', '255.255.255.128')

        ip = IPNetwork(cidr)
        mask = ip.netmask

        if azs == 3:
            if str(mask) not in netmasks[0:3]:
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

    def vpc_creation(self, session, cidr):

        vpc_resp = session.ec2.create_vpc(
            DryRun=False,
            CidrBlock=cidr,
            InstanceTenancy='default',
        )
        vpc_id = vpc_resp['Vpc']['VpcId']
        # print("Created VPC: {0}".format(vpc_id))

        # session.ec2.get_waiter('vpc_available').wait(VpcIds=[vpc_id])

        # session.ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={'Value': True})
        # session.ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={'Value': True})

        # create_tags(vpc_id, vpc_name_tag, ec2c, deployed_environment)
        # print("VPC: {0} is now available. Continuing".format(vpc_id))
        return vpc_id

    def create_subnets(self, session, vpc_id, zones, sizing):
        i = 0
        azs = len(zones)
        sub_ids = []
        tier = 'public'
        for sub in sizing:
            subnet = session.ec2.create_subnet(
                DryRun=False,
                VpcId=vpc_id,
                CidrBlock=str(sub),
                AvailabilityZone=zones[i])
            sub_ids.append(subnet['Subnet']['SubnetId'])
            print("sub-id: ", sub_ids[i], "\tsize: ", sub, "\tzone: ", zones[i])
            i += 1
            if i == azs:
                i = 0
                tier = 'private'
        return sub_ids

    def create_igw(self, session, vpc_id):

        response = session.ec2.create_internet_gateway()
        igw_id = response['InternetGateway']['InternetGatewayId']
        session.ec2.attach_internet_gateway(
            DryRun=False,
            InternetGatewayId=igw_id,
            VpcId=vpc_id
        )
        return igw_id

    def create_routes(self, session, zones, vpc_id, igw, subnets):
        azs = len(zones)
        i = 0
        rtb_ids = []
        tier = 'public'

        for sub in subnets:
            if i == 0:
                response = session.ec2.create_route_table(
                    DryRun=False,
                    VpcId=vpc_id
                )
                rtb_id = response['RouteTable']['RouteTableId']
                session.ec2.create_route(
                    DryRun=False,
                    RouteTableId=rtb_id,
                    DestinationCidrBlock='0.0.0.0/0',
                    GatewayId=igw
                )
                rtb_ids.append(rtb_id)
            session.ec2.associate_route_table(
                DryRun=False,
                SubnetId=sub,
                RouteTableId=rtb_id
            )
            i += 1

            if i == azs:
                i = 0
                tier = 'private'

        return rtb_ids

    def create_acl(self, session, zones, vpc_id, subnets, cidr):
        azs = len(zones)
        i = 0;
        acl_ids = []
        naclassoclist = []
        tier = 'public'
        for sub in subnets:
            if i == 0:
                response = session.ec2.describe_network_acls(
                    DryRun=False,
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]},
                             {'Name': 'association.subnet-id', 'Values': [subnets[i]]}, ])
                for
                currentacl = str(response)
                idspos1 = currentacl.find('aclassoc-')
                print(idspos1)
                defaultassocid = (currentacl[idspos1:149])
                print(defaultassocid)
                naclassoclist.append(defaultassocid)

                response = session.ec2.create_network_acl(
                    DryRun=False,
                    VpcId=vpc_id
                )
                acl_id = response['NetworkAcl']['NetworkAclId']
                session.ec2.create_network_acl_entry(DryRun=False,NetworkAclId=acl_id,RuleNumber=100,Protocol='-1',\
                                                     RuleAction='allow',Egress=False, CidrBlock='0.0.0.0/0')
                session.ec2.create_network_acl_entry(DryRun=False, NetworkAclId=acl_id, RuleNumber=200, Protocol='6',\
                                                     RuleAction='allow', Egress=False, CidrBlock='0.0.0.0/0',\
                                                     PortRange={'From': 22, 'To': 22})
                session.ec2.create_network_acl_entry(DryRun=False, NetworkAclId=acl_id, RuleNumber=300, Protocol='6',\
                                                     RuleAction='allow', Egress=False, CidrBlock='0.0.0.0/0',\
                                                     PortRange={'From': 80, 'To': 80})
                session.ec2.create_network_acl_entry(DryRun=False, NetworkAclId=acl_id, RuleNumber=400, Protocol='6',\
                                                     RuleAction='allow', Egress=False, CidrBlock='0.0.0.0/0',\
                                                     PortRange={'From': 443, 'To': 443})
                session.ec2.create_network_acl_entry(DryRun=False, NetworkAclId=acl_id, RuleNumber=500, Protocol='6',\
                                                     RuleAction='allow', Egress=False, CidrBlock='0.0.0.0/0',\
                                                     PortRange={'From': 3389, 'To': 3389})
                acl_ids.append(acl_id)

                print(acl_ids)

            session.ec2.replace_network_acl_association(DryRun=False,AssociationId=acl_id,NetworkAclId=sub)
            i += 1
            if i == azs: i = 0; tier = 'private'

        return acl_ids


def main(cidr, arn, region):

    session = AWSSession(
        arn=arn,
        region=region,
        role_session_name='vpc_sts'
    )
    session.role_arn_to_session()
    vpc_establishment = AWSNetworking()
    vpc_id = vpc_establishment.vpc_creation(session, cidr)
    igw = vpc_establishment.create_igw(session, vpc_id)
    zones = vpc_establishment.zone_availability(session)
    sizing = vpc_establishment.subnet_size(zones, cidr)
    subnets = vpc_establishment.create_subnets(session, vpc_id, zones, sizing)
    routes = vpc_establishment.create_routes(session, zones, vpc_id, igw, subnets)
    nacls = vpc_establishment.create_acl(session, zones, vpc_id, subnets, cidr)
    return 0

if __name__ == "__main__":
    main(cidr='10.192.0.0/22', arn='arn:aws:iam::628936956560:role/StrutCrossAccountAdmins', region='ap-southeast-2')
    # main(cidr='10.192.0.0/20', arn='arn:aws:iam::236721185431:role/quantium-ss-admin', region='ap-southeast-2')