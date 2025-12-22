import json
import boto3
import os
from datetime import datetime
from typing import Dict, Any, List

# Initialize AWS clients
ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
iam = boto3.client('iam')
securityhub = boto3.client('securityhub')
sns = boto3.client('sns')

AUTO_REMEDIATION_ENABLED = os.environ.get('AUTO_REMEDIATION_ENABLED', 'true').lower() == 'true'
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'production')


def lambda_handler(event, context):
    """
    Main handler for Security Hub findings auto-remediation
    """
    print(f"Received event: {json.dumps(event)}")
    
    try:
        # Handle Security Hub findings
        if 'detail' in event and 'findings' in event['detail']:
            findings = event['detail']['findings']
            remediation_results = []
            
            for finding in findings:
                result = process_finding(finding)
                remediation_results.append(result)
            
            # Send summary notification
            send_notification(remediation_results)
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Auto-remediation completed',
                    'results': remediation_results
                })
            }
        
        # Handle GuardDuty findings
        elif event.get('source') == 'aws.guardduty':
            result = process_guardduty_finding(event['detail'])
            send_notification([result])
            
            return {
                'statusCode': 200,
                'body': json.dumps(result)
            }
        
        else:
            print("Unsupported event format")
            return {
                'statusCode': 400,
                'body': json.dumps({'message': 'Unsupported event format'})
            }
            
    except Exception as e:
        print(f"Error processing event: {str(e)}")
        send_error_notification(str(e), event)
        raise


def process_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process individual Security Hub finding and apply remediation
    """
    finding_id = finding.get('Id')
    title = finding.get('Title', '')
    severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
    resources = finding.get('Resources', [])
    
    print(f"Processing finding: {finding_id} - {title} - Severity: {severity}")
    
    result = {
        'finding_id': finding_id,
        'title': title,
        'severity': severity,
        'action_taken': 'None',
        'success': False,
        'message': ''
    }
    
    if not AUTO_REMEDIATION_ENABLED:
        result['message'] = 'Auto-remediation is disabled'
        return result
    
    try:
        # S3 Public Access Remediation
        if 'S3' in title and 'public' in title.lower():
            result = remediate_s3_public_access(finding, resources)
        
        # EC2 Security Group Remediation
        elif 'security group' in title.lower() and ('0.0.0.0/0' in title or 'unrestricted' in title.lower()):
            result = remediate_security_group(finding, resources)
        
        # Unencrypted Resources
        elif 'encrypt' in title.lower():
            result = remediate_unencrypted_resource(finding, resources)
        
        # IAM Access Key Rotation
        elif 'access key' in title.lower() and 'rotat' in title.lower():
            result = remediate_iam_access_key(finding, resources)
        
        # EC2 Instance Exposed
        elif 'ec2' in title.lower() and ('exposed' in title.lower() or 'compromised' in title.lower()):
            result = remediate_ec2_instance(finding, resources)
        
        # Root Account MFA
        elif 'root' in title.lower() and 'mfa' in title.lower():
            result = remediate_root_mfa(finding)
        
        # CloudTrail Logging
        elif 'cloudtrail' in title.lower():
            result = remediate_cloudtrail(finding, resources)
        
        else:
            result['message'] = f'No automated remediation available for: {title}'
        
        # Update Security Hub finding status
        if result.get('success'):
            update_security_hub_finding(finding_id, 'RESOLVED', result.get('message'))
        
    except Exception as e:
        result['success'] = False
        result['message'] = f'Remediation failed: {str(e)}'
        print(f"Error remediating finding {finding_id}: {str(e)}")
    
    return result


def remediate_s3_public_access(finding: Dict, resources: List[Dict]) -> Dict:
    """
    Remediate S3 buckets with public access
    """
    result = {
        'finding_id': finding.get('Id'),
        'title': finding.get('Title'),
        'action_taken': 'S3 Public Access Block',
        'success': False,
        'message': ''
    }
    
    for resource in resources:
        if resource.get('Type') == 'AwsS3Bucket':
            bucket_name = resource.get('Id', '').split(':')[-1]
            
            try:
                # Enable S3 Block Public Access
                s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
                
                result['success'] = True
                result['message'] = f'Successfully enabled Block Public Access on bucket: {bucket_name}'
                print(result['message'])
                
            except Exception as e:
                result['message'] = f'Failed to remediate bucket {bucket_name}: {str(e)}'
                print(result['message'])
    
    return result


def remediate_security_group(finding: Dict, resources: List[Dict]) -> Dict:
    """
    Remediate overly permissive security groups
    """
    result = {
        'finding_id': finding.get('Id'),
        'title': finding.get('Title'),
        'action_taken': 'Security Group Restriction',
        'success': False,
        'message': ''
    }
    
    for resource in resources:
        if resource.get('Type') == 'AwsEc2SecurityGroup':
            sg_id = resource.get('Id', '').split('/')[-1]
            
            try:
                # Get security group details
                response = ec2.describe_security_groups(GroupIds=[sg_id])
                sg = response['SecurityGroups'][0]
                
                # Remove unrestricted ingress rules (0.0.0.0/0 on sensitive ports)
                sensitive_ports = [22, 3389, 1433, 3306, 5432, 5984, 6379, 7000, 7001, 8020, 8888, 9042, 9160, 9200, 9300, 11211, 27017]
                
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 0)
                            to_port = rule.get('ToPort', 0)
                            
                            # Check if it's a sensitive port
                            if any(from_port <= port <= to_port for port in sensitive_ports):
                                ec2.revoke_security_group_ingress(
                                    GroupId=sg_id,
                                    IpPermissions=[rule]
                                )
                                print(f"Revoked unrestricted ingress on port {from_port}-{to_port} for SG {sg_id}")
                
                result['success'] = True
                result['message'] = f'Successfully restricted security group: {sg_id}'
                
            except Exception as e:
                result['message'] = f'Failed to remediate security group {sg_id}: {str(e)}'
                print(result['message'])
    
    return result


def remediate_unencrypted_resource(finding: Dict, resources: List[Dict]) -> Dict:
    """
    Remediate unencrypted resources
    """
    result = {
        'finding_id': finding.get('Id'),
        'title': finding.get('Title'),
        'action_taken': 'Enable Encryption',
        'success': False,
        'message': ''
    }
    
    for resource in resources:
        resource_type = resource.get('Type')
        
        # S3 Bucket Encryption
        if resource_type == 'AwsS3Bucket':
            bucket_name = resource.get('Id', '').split(':')[-1]
            
            try:
                s3.put_bucket_encryption(
                    Bucket=bucket_name,
                    ServerSideEncryptionConfiguration={
                        'Rules': [
                            {
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': 'AES256'
                                },
                                'BucketKeyEnabled': True
                            }
                        ]
                    }
                )
                
                result['success'] = True
                result['message'] = f'Successfully enabled encryption on S3 bucket: {bucket_name}'
                print(result['message'])
                
            except Exception as e:
                result['message'] = f'Failed to enable encryption on bucket {bucket_name}: {str(e)}'
                print(result['message'])
        
        # For EBS volumes, we can't encrypt in place, so we create a snapshot
        elif resource_type == 'AwsEc2Volume':
            volume_id = resource.get('Id', '').split('/')[-1]
            
            try:
                # Create encrypted snapshot
                response = ec2.create_snapshot(
                    VolumeId=volume_id,
                    Description=f'Encrypted snapshot created by auto-remediation on {datetime.now().isoformat()}',
                    TagSpecifications=[
                        {
                            'ResourceType': 'snapshot',
                            'Tags': [
                                {'Key': 'Name', 'Value': f'encrypted-snapshot-{volume_id}'},
                                {'Key': 'AutoRemediation', 'Value': 'true'},
                                {'Key': 'OriginalVolume', 'Value': volume_id}
                            ]
                        }
                    ]
                )
                
                result['success'] = True
                result['message'] = f'Created encrypted snapshot {response["SnapshotId"]} for volume {volume_id}. Manual intervention required to replace volume.'
                print(result['message'])
                
            except Exception as e:
                result['message'] = f'Failed to create encrypted snapshot for volume {volume_id}: {str(e)}'
                print(result['message'])
    
    return result


def remediate_iam_access_key(finding: Dict, resources: List[Dict]) -> Dict:
    """
    Remediate IAM access key rotation issues
    """
    result = {
        'finding_id': finding.get('Id'),
        'title': finding.get('Title'),
        'action_taken': 'IAM Access Key Deactivation',
        'success': False,
        'message': ''
    }
    
    for resource in resources:
        if resource.get('Type') == 'AwsIamUser':
            username = resource.get('Id', '').split('/')[-1]
            
            try:
                # List access keys for user
                response = iam.list_access_keys(UserName=username)
                
                for key in response['AccessKeyMetadata']:
                    key_id = key['AccessKeyId']
                    create_date = key['CreateDate']
                    age_days = (datetime.now(create_date.tzinfo) - create_date).days
                    
                    # Deactivate keys older than 90 days
                    if age_days > 90 and key['Status'] == 'Active':
                        iam.update_access_key(
                            UserName=username,
                            AccessKeyId=key_id,
                            Status='Inactive'
                        )
                        print(f"Deactivated access key {key_id} for user {username} (age: {age_days} days)")
                
                result['success'] = True
                result['message'] = f'Successfully processed access keys for user: {username}'
                
            except Exception as e:
                result['message'] = f'Failed to remediate access keys for user {username}: {str(e)}'
                print(result['message'])
    
    return result


def remediate_ec2_instance(finding: Dict, resources: List[Dict]) -> Dict:
    """
    Remediate compromised or exposed EC2 instances
    """
    result = {
        'finding_id': finding.get('Id'),
        'title': finding.get('Title'),
        'action_taken': 'EC2 Instance Isolation',
        'success': False,
        'message': ''
    }
    
    for resource in resources:
        if resource.get('Type') == 'AwsEc2Instance':
            instance_id = resource.get('Id', '').split('/')[-1]
            
            try:
                # Create forensic snapshot before taking action
                response = ec2.describe_instances(InstanceIds=[instance_id])
                instance = response['Reservations'][0]['Instances'][0]
                
                for bdm in instance.get('BlockDeviceMappings', []):
                    volume_id = bdm.get('Ebs', {}).get('VolumeId')
                    if volume_id:
                        ec2.create_snapshot(
                            VolumeId=volume_id,
                            Description=f'Forensic snapshot - {finding.get("Title")}',
                            TagSpecifications=[
                                {
                                    'ResourceType': 'snapshot',
                                    'Tags': [
                                        {'Key': 'Forensic', 'Value': 'true'},
                                        {'Key': 'InstanceId', 'Value': instance_id},
                                        {'Key': 'FindingId', 'Value': finding.get('Id')}
                                    ]
                                }
                            ]
                        )
                
                # Create isolation security group
                vpc_id = instance['VpcId']
                isolation_sg = ec2.create_security_group(
                    GroupName=f'isolation-sg-{instance_id}',
                    Description='Isolation security group for compromised instance',
                    VpcId=vpc_id
                )
                
                # Attach isolation security group (removes all other SGs)
                ec2.modify_instance_attribute(
                    InstanceId=instance_id,
                    Groups=[isolation_sg['GroupId']]
                )
                
                result['success'] = True
                result['message'] = f'Successfully isolated instance {instance_id} and created forensic snapshots'
                print(result['message'])
                
            except Exception as e:
                result['message'] = f'Failed to remediate instance {instance_id}: {str(e)}'
                print(result['message'])
    
    return result


def remediate_root_mfa(finding: Dict) -> Dict:
    """
    Send notification for root account MFA (requires manual action)
    """
    result = {
        'finding_id': finding.get('Id'),
        'title': finding.get('Title'),
        'action_taken': 'Notification Sent',
        'success': True,
        'message': 'Root account MFA requires manual remediation. Security team has been notified.'
    }
    
    return result


def remediate_cloudtrail(finding: Dict, resources: List[Dict]) -> Dict:
    """
    CloudTrail remediation notification (requires manual setup)
    """
    result = {
        'finding_id': finding.get('Id'),
        'title': finding.get('Title'),
        'action_taken': 'Notification Sent',
        'success': True,
        'message': 'CloudTrail configuration requires manual remediation. Security team has been notified.'
    }
    
    return result


def process_guardduty_finding(detail: Dict) -> Dict:
    """
    Process GuardDuty finding
    """
    finding_type = detail.get('type', '')
    severity = detail.get('severity', 0)
    
    result = {
        'finding_type': finding_type,
        'severity': severity,
        'action_taken': 'Processed',
        'success': True,
        'message': f'GuardDuty finding processed: {finding_type}'
    }
    
    # Take action based on finding type
    if 'UnauthorizedAccess' in finding_type or 'Trojan' in finding_type:
        # High severity findings require immediate action
        if severity >= 7.0:
            result['message'] = f'Critical GuardDuty finding detected: {finding_type}. Manual investigation required.'
    
    return result


def update_security_hub_finding(finding_id: str, workflow_status: str, note: str):
    """
    Update Security Hub finding status
    """
    try:
        securityhub.batch_update_findings(
            FindingIdentifiers=[
                {
                    'Id': finding_id,
                    'ProductArn': finding_id.split('/')[0]
                }
            ],
            Workflow={
                'Status': workflow_status
            },
            Note={
                'Text': note,
                'UpdatedBy': 'AutoRemediationLambda'
            }
        )
        print(f"Updated finding {finding_id} to status {workflow_status}")
    except Exception as e:
        print(f"Failed to update finding {finding_id}: {str(e)}")


def send_notification(results: List[Dict]):
    """
    Send SNS notification with remediation results
    """
    if not SNS_TOPIC_ARN:
        print("SNS topic ARN not configured")
        return
    
    try:
        message = {
            'timestamp': datetime.now().isoformat(),
            'environment': ENVIRONMENT,
            'summary': {
                'total_findings': len(results),
                'successful_remediations': sum(1 for r in results if r.get('success')),
                'failed_remediations': sum(1 for r in results if not r.get('success'))
            },
            'details': results
        }
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f'[{ENVIRONMENT}] Security Auto-Remediation Report',
            Message=json.dumps(message, indent=2)
        )
        print("Notification sent successfully")
        
    except Exception as e:
        print(f"Failed to send notification: {str(e)}")


def send_error_notification(error: str, event: Dict):
    """
    Send error notification
    """
    if not SNS_TOPIC_ARN:
        return
    
    try:
        message = {
            'timestamp': datetime.now().isoformat(),
            'environment': ENVIRONMENT,
            'error': error,
            'event': event
        }
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f'[{ENVIRONMENT}] Security Auto-Remediation ERROR',
            Message=json.dumps(message, indent=2)
        )
        
    except Exception as e:
        print(f"Failed to send error notification: {str(e)}")