#!/usr/bin/env bash
# Detonator burner — launch a hardened, credential-free EC2 detonation host.
#
# You run this LOCALLY with the AWS CLI configured. It only provisions
# infrastructure — nothing malicious runs on your machine or in this script.
# burner-setup.sh must sit next to this file (it is uploaded as EC2 user-data).
set -euo pipefail

### ---- fill these in ----
REGION="${REGION:-us-east-1}"
KEY_NAME="${KEY_NAME:?set KEY_NAME to an existing EC2 key pair name in this region}"
MY_IP="${MY_IP:?set MY_IP to your public IP, e.g. run: curl -s https://checkip.amazonaws.com}"
INSTANCE_TYPE="${INSTANCE_TYPE:-t3.large}"   # 2 vCPU / 8 GB. gVisor uses ptrace/systrap — no KVM / .metal needed.
### ----------------------

# Latest Ubuntu 24.04 LTS AMI via Canonical's public SSM parameter (no hardcoded, region-specific AMI id).
AMI_ID=$(aws ssm get-parameters --region "$REGION" \
  --names /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
  --query 'Parameters[0].Value' --output text)
echo "AMI:            $AMI_ID"

# Security group: inbound SSH from your IP only. Egress is left open because Phase 0
# needs to pull the Docker image + benign packages; we tighten the *sandbox's* egress
# to a sinkhole before any live-corpus run (Phase 3), not the host's during Phase 0.
SG_ID=$(aws ec2 create-security-group --region "$REGION" \
  --group-name "detonator-burner-sg-$(date +%s 2>/dev/null || echo 0)" \
  --description "Detonator burner - SSH from my IP only" \
  --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --region "$REGION" \
  --group-id "$SG_ID" --protocol tcp --port 22 --cidr "${MY_IP}/32" >/dev/null
echo "Security group: $SG_ID (ssh from ${MY_IP}/32)"

# Launch. The deliberate hardening:
#   * NO --iam-instance-profile   -> the instance carries ZERO AWS credentials
#   * --metadata-options disabled -> 169.254.169.254 (IMDS) answers nothing, even if reached
#   * shutdown-behavior terminate -> `sudo shutdown -h now` on the box destroys it ("burn per batch")
#   * encrypted root volume, deleted on termination
INSTANCE_ID=$(aws ec2 run-instances --region "$REGION" \
  --image-id "$AMI_ID" --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" --security-group-ids "$SG_ID" \
  --metadata-options "HttpEndpoint=disabled" \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":40,"VolumeType":"gp3","Encrypted":true,"DeleteOnTermination":true}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=detonator-burner},{Key=purpose,Value=malware-detonation},{Key=ephemeral,Value=true}]' \
  --user-data file://burner-setup.sh \
  --instance-initiated-shutdown-behavior terminate \
  --count 1 --query 'Instances[0].InstanceId' --output text)
echo "Instance:       $INSTANCE_ID (launching…)"

aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"
IP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

cat <<EOF

  Burner is up.
    SSH:        ssh ubuntu@${IP}
    Watch setup: ssh ubuntu@${IP} 'cloud-init status --wait && cat /opt/BURNER_READY'
    Terminate:   aws ec2 terminate-instances --region ${REGION} --instance-ids ${INSTANCE_ID}
                 aws ec2 delete-security-group   --region ${REGION} --group-id ${SG_ID}

  Setup takes ~3-5 min (installs Docker + gVisor + package-analysis). Then follow RUNBOOK.md.
EOF
