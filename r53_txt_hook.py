#!/usr/bin/env python
"""
Obtains hostname and creates TXT entry in Route53 cross account Hosted Zone for Let's Encrypt challenge.

Parameters
    ----------
    arg1 : -t or --txt
        TXT value for DNS from Let's Encrypt
    arg2 : -o or --option
        Either deploy_challenge to create entry or clean_challenge to remove entry

    Returns
    -------
    int
        0

    Examples
    -------
    ./r53_txt_update.py -t "getdg345263254tgfv" -o deploy_challenge
    ./r53_txt_update.py -t "getdg345263254tgfv" -o clean_challenge

"""

from __future__ import print_function

import socket
from collections import namedtuple

import boto3
import requests
import argparse

parser = argparse.ArgumentParser(description='Parameters and arguments required for route53 update.')
parser.add_argument('-t', '--txt', help='TXT value', dest='txt', required=True)
parser.add_argument('-o', '--option', help='Either deploy_challenge or clean_challenge', dest='hook', required=True)

Instance = namedtuple('Instance', ('ip', 'name'))
args = parser.parse_args()
txt_value = args.txt
hook = args.hook


class AWSSession(object):
    def __init__(self, hosted_zone_id, arn, region, role_session_name, txt_value):
        self.hosted_zone_id = hosted_zone_id
        self.arn = arn
        self.region = region
        self.role_session_name = role_session_name
        self._token = None
        self._r53 = None
        self._instance = None
        self._aws_access_key_id = None
        self._aws_secret_access_key = None
        self._aws_session_token = None
        self.txt_value = txt_value

    @property
    def token(self):
        return self._token or self.role_arn_to_session()

    @property
    def r53(self):
        return self._r53 or self.connect_to_r53()

    @property
    def instance(self):
        return self._instance or self.get_instance()

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

    def connect_to_r53(self):
        self._r53 = boto3.client('route53',
                                 aws_access_key_id=self._aws_access_key_id[0],
                                 aws_secret_access_key=self._aws_secret_access_key[0],
                                 aws_session_token=self._aws_session_token[0],
                                 )
        return self._r53

    def get_instance(self):
        ec2 = boto3.resource('ec2', region_name=self.region)
        instance_id = requests.get('http://169.254.169.254/latest/meta-data/instance-id').text
        instance = ec2.Instance(instance_id)
        instance_ip = instance.private_ip_address
        instance_name = socket.gethostname()
        self._instance = Instance(ip=instance_ip, name=instance_name)
        return self._instance


class DNSHandler(object):
    def dns_update(self, session):
        dns_changes = {
            'Changes': [
                {
                    'Action':            'UPSERT',
                    'ResourceRecordSet': {
                        'Name':            "_acme-challenge."+session.instance.name,
                        'Type':            'TXT',
                        'TTL':             60,
                        'ResourceRecords': [
                            {
                                'Value': '"'+session.txt_value+'"'
                            }
                        ]
                    }
                }
            ]
        }

        response = session.r53.change_resource_record_sets(
            HostedZoneId=session.hosted_zone_id,
            ChangeBatch=dns_changes
        )
        change_id = response['ChangeInfo']['Id']
        waiter = session.r53.get_waiter('resource_record_sets_changed')
        waiter.wait(
            Id=change_id
        )
        change_status = session.r53.get_change(
            Id=change_id
        )
        return change_status

    def dns_delete(self, session):
        dns_changes = {
            'Changes': [
                {
                    'Action':            'DELETE',
                    'ResourceRecordSet': {
                        'Name':            "_acme-challenge."+session.instance.name,
                        'Type':            'TXT',
                        'TTL':             60,
                        'ResourceRecords': [
                            {
                                'Value': '"'+session.txt_value+'"'
                            }
                        ]
                    }
                }
            ]
        }

        response = session.r53.change_resource_record_sets(
            HostedZoneId=session.hosted_zone_id,
            ChangeBatch=dns_changes
        )
        change_id = response['ChangeInfo']['Id']
        waiter = session.r53.get_waiter('resource_record_sets_changed')
        waiter.wait(
            Id=change_id
        )
        change_status = session.r53.get_change(
            Id=change_id
        )
        return change_status


def main():
    session = AWSSession(
        hosted_zone_id='Z2YQOOCPCZ6LZ0',
        arn='arn:aws:iam::787109557840:role/iam_sts_r53',
        region='ap-southeast-2',
        role_session_name='r53_sts',
        txt_value=txt_value,
    )
    session.role_arn_to_session()
    dns_handler = DNSHandler()
    if hook == "deploy_challenge":
        update_record = dns_handler.dns_update(session)
        print(update_record)
    elif hook == "clean_challenge":
        delete_record = dns_handler.dns_delete(session)
        print(delete_record)
    return 0

if __name__ == "__main__":
    main()

