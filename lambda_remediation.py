import json
import os
import boto3
from datetime import datetime

# Clientes AWS
ec2 = boto3.client('ec2')
s3 = boto3.client('s3')
iam = boto3.client('iam')
sns = boto3.client('sns')

# Variables de entorno
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
AUTO_REMEDIATE = os.environ.get('AUTO_REMEDIATE', 'false').lower() == 'true'


def lambda_handler(event, context):
    """
    Función principal activada por EventBridge cuando Config detecta NON_COMPLIANT
    """
    print(f"🔧 Auto-remediation triggered: {json.dumps(event)}")
    
    # Extraer detalles del evento
    config_rule_name = event['detail']['configRuleName']
    resource_type = event['detail']['resourceType']
    resource_id = event['detail']['resourceId']
    compliance_type = event['detail']['newEvaluationResult']['complianceType']

    if compliance_type != 'NON_COMPLIANT':
        print(f"✅ Resource {resource_id} is compliant")
        return

    print(f"⚠️  NON_COMPLIANT: {config_rule_name} - {resource_type} - {resource_id}")

    # Decidir qué remediar según la regla
    remediation_result = None

    if config_rule_name == "s3-bucket-server-side-encryption-enabled":
        remediation_result = remediate_s3_encryption(resource_id)

    elif config_rule_name == "encrypted-volumes":
        remediation_result = remediate_ebs_encryption(resource_id)

    elif config_rule_name == "restricted-ssh":
        remediation_result = remediate_open_ssh(resource_id)

    else:
        print(f"ℹ️  No automated remediation for rule: {config_rule_name}")
        return

    # Enviar reporte si se remedió algo
    if remediation_result:
        send_remediation_report(config_rule_name, resource_id, remediation_result)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'rule': config_rule_name,
            'resource': resource_id,
            'remediated': remediation_result is not None
        })
    }


def remediate_s3_encryption(bucket_name):
    """
    Habilita encriptación AES256 en bucket S3
    """
    if not AUTO_REMEDIATE:
        print(f"🔒 AUTO_REMEDIATE disabled - would encrypt bucket: {bucket_name}")
        return None
    
    try:
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )
        print(f"✅ Enabled encryption on S3 bucket: {bucket_name}")
        return f"Enabled AES256 encryption on bucket {bucket_name}"
    
    except Exception as e:
        print(f"❌ Error encrypting bucket {bucket_name}: {e}")
        return None


def remediate_ebs_encryption(volume_id):
    """
    Crea snapshot encriptado del volumen EBS y notifica
    (No elimina el volumen original - requiere intervención manual)
    """
    if not AUTO_REMEDIATE:
        print(f"🔒 AUTO_REMEDIATE disabled - would create encrypted snapshot: {volume_id}")
        return None
    
    try:
        # Crear snapshot encriptado
        response = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"Encrypted snapshot of {volume_id}",
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot',
                    'Tags': [
                        {'Key': 'OriginalVolume', 'Value': volume_id},
                        {'Key': 'AutoRemediation', 'Value': 'true'}
                    ]
                }
            ]
        )
        
        snapshot_id = response['SnapshotId']
        
        # Copiar snapshot con encriptación
        encrypted_snapshot = ec2.copy_snapshot(
            SourceSnapshotId=snapshot_id,
            SourceRegion=ec2.meta.region_name,
            Description=f"Encrypted copy of {snapshot_id}",
            Encrypted=True
        )
        
        print(f"✅ Created encrypted snapshot: {encrypted_snapshot['SnapshotId']}")
        return f"Created encrypted snapshot {encrypted_snapshot['SnapshotId']} from {volume_id}. Manual action required: replace volume."
    
    except Exception as e:
        print(f"❌ Error creating encrypted snapshot for {volume_id}: {e}")
        return None


def remediate_open_ssh(security_group_id):
    """
    Elimina reglas que permiten SSH (puerto 22) desde 0.0.0.0/0
    """
    if not AUTO_REMEDIATE:
        print(f"🔒 AUTO_REMEDIATE disabled - would restrict SSH in SG: {security_group_id}")
        return None
    
    try:
        # Obtener reglas del Security Group
        response = ec2.describe_security_groups(GroupIds=[security_group_id])
        sg = response['SecurityGroups'][0]
        
        rules_removed = []
        
        for rule in sg['IpPermissions']:
            # Buscar reglas SSH (puerto 22) abiertas al mundo
            if rule.get('FromPort') == 22 and rule.get('ToPort') == 22:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        # Eliminar regla peligrosa
                        ec2.revoke_security_group_ingress(
                            GroupId=security_group_id,
                            IpPermissions=[rule]
                        )
                        rules_removed.append(f"SSH from 0.0.0.0/0")
        
        if rules_removed:
            print(f"✅ Removed open SSH rules from {security_group_id}: {rules_removed}")
            return f"Removed {len(rules_removed)} open SSH rule(s) from {security_group_id}"
        else:
            print(f"ℹ️  No open SSH rules found in {security_group_id}")
            return None
    
    except Exception as e:
        print(f"❌ Error remediating SG {security_group_id}: {e}")
        return None


def send_remediation_report(rule_name, resource_id, action_taken):
    """
    Envía reporte de remediación a SNS
    """
    message = f"""
🔧 AUTOMATIC REMEDIATION EXECUTED

Rule: {rule_name}
Resource: {resource_id}
Action: {action_taken}
Timestamp: {datetime.now().isoformat()}

Review the change in AWS Console.
"""
    
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"Security Auto-Remediation: {rule_name}",
            Message=message
        )
        print("📧 Remediation report sent to SNS")
    except Exception as e:
        print(f"❌ Error sending SNS: {e}")
