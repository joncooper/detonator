#!/usr/bin/env bash
# Detonator burner — launch a hardened, credential-free EC2 detonation host.
#
# You run this LOCALLY with the AWS CLI configured. It only provisions
# infrastructure — nothing malicious runs on your machine or in this script.
# burner-setup.sh must sit next to this file (it is uploaded as EC2 user-data).
set -euo pipefail

### ---- fill these in ----
REGION="${REGION:-us-east-1}"
MY_IP="${MY_IP:?set MY_IP to your public IP, e.g. run: curl -s https://checkip.amazonaws.com}"
INSTANCE_TYPE="${INSTANCE_TYPE:-t3.large}"   # 2 vCPU / 8 GB. gVisor uses ptrace/systrap — no KVM / .metal needed.
# KEY_NAME is optional: leave it unset and the script mints a dedicated key pair
# for this burner and writes the private key next to this script. Set it only to
# reuse an existing EC2 key pair.
### ----------------------

# Preflight: confirm credentials resolve before we start creating resources.
# SSO logins cache under a profile — export AWS_PROFILE so the CLI finds them.
if ! aws sts get-caller-identity --region "$REGION" >/dev/null 2>&1; then
  echo "ERROR: no working AWS credentials for region $REGION." >&2
  echo "If you use SSO, log in and select the profile in this shell, e.g.:" >&2
  echo "    aws sso login --profile <your-profile>" >&2
  echo "    export AWS_PROFILE=<your-profile>" >&2
  exit 1
fi

STAMP="$(date +%s 2>/dev/null || echo 0)"

# Mint a burner-only SSH key unless the caller supplied one. AWS generates the
# key pair and hands back the private key, which we save locally (0600). It is
# torn down with the instance — a throwaway key for a throwaway host.
MINTED_KEY=0
if [ -z "${KEY_NAME:-}" ]; then
  KEY_NAME="detonator-burner-${STAMP}"
  PEM="$(cd "$(dirname "$0")" && pwd)/${KEY_NAME}.pem"
  aws ec2 create-key-pair --region "$REGION" --key-name "$KEY_NAME" \
    --query 'KeyMaterial' --output text > "$PEM"
  chmod 600 "$PEM"
  MINTED_KEY=1
  echo "Key pair:       $KEY_NAME (minted; private key at $PEM)"
else
  echo "Key pair:       $KEY_NAME (pre-existing; use your own private key to SSH)"
fi

# Latest Ubuntu 24.04 LTS AMI via Canonical's public SSM parameter (no hardcoded, region-specific AMI id).
AMI_ID=$(aws ssm get-parameters --region "$REGION" \
  --names /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
  --query 'Parameters[0].Value' --output text)
echo "AMI:            $AMI_ID"

# Security group: inbound SSH from your IP only. Egress is left open because Phase 0
# needs to pull the Docker image + benign packages; we tighten the *sandbox's* egress
# to a sinkhole before any live-corpus run (Phase 3), not the host's during Phase 0.
SG_ID=$(aws ec2 create-security-group --region "$REGION" \
  --group-name "detonator-burner-sg-${STAMP}" \
  --description "Detonator burner - SSH from my IP only" \
  --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --region "$REGION" \
  --group-id "$SG_ID" --protocol tcp --port 22 --cidr "${MY_IP}/32" >/dev/null
echo "Security group: $SG_ID (ssh from ${MY_IP}/32)"

# Launch. The deliberate hardening:
#   * NO --iam-instance-profile   -> the instance carries ZERO AWS credentials,
#     so IMDS exposes nothing worth stealing even while it is reachable.
#   * IMDSv2 required + hop limit 1 -> the metadata endpoint stays reachable for
#     cloud-init at first boot (it fetches the SSH key AND the user-data script
#     from IMDS — disabling it at launch breaks provisioning entirely), but a
#     token is required and the 1-hop TTL blocks the container/pod escape path
#     (the 2020 GKE metadata-API vector). burner-setup.sh then iptables-blackholes
#     IMDS once provisioning is done — belt-and-suspenders, at the right moment.
#   * shutdown-behavior terminate -> `sudo shutdown -h now` on the box destroys it ("burn per batch")
#   * encrypted root volume, deleted on termination
INSTANCE_ID=$(aws ec2 run-instances --region "$REGION" \
  --image-id "$AMI_ID" --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" --security-group-ids "$SG_ID" \
  --metadata-options "HttpEndpoint=enabled,HttpTokens=required,HttpPutResponseHopLimit=1" \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":40,"VolumeType":"gp3","Encrypted":true,"DeleteOnTermination":true}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=detonator-burner},{Key=purpose,Value=malware-detonation},{Key=ephemeral,Value=true}]' \
  --user-data file://burner-setup.sh \
  --instance-initiated-shutdown-behavior terminate \
  --count 1 --query 'Instances[0].InstanceId' --output text)
echo "Instance:       $INSTANCE_ID (launching…)"

aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"
IP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

# SSH invocation + teardown vary depending on whether we minted the key.
if [ "$MINTED_KEY" = "1" ]; then
  SSH_CMD="ssh -i ${PEM} ubuntu@${IP}"
  KEY_TEARDOWN="aws ec2 delete-key-pair --region ${REGION} --key-name ${KEY_NAME}; rm -f ${PEM}"
else
  SSH_CMD="ssh ubuntu@${IP}"
  KEY_TEARDOWN="# (using your own key pair ${KEY_NAME}; nothing to delete)"
fi

cat <<EOF

  Burner is up.
    SSH:         ${SSH_CMD}
    Watch setup: ${SSH_CMD} 'cloud-init status --wait && cat /opt/BURNER_READY'
    Terminate:   aws ec2 terminate-instances --region ${REGION} --instance-ids ${INSTANCE_ID}
                 aws ec2 delete-security-group   --region ${REGION} --group-id ${SG_ID}
                 ${KEY_TEARDOWN}

  Setup takes ~3-5 min (installs Docker + gVisor + package-analysis). Then follow RUNBOOK.md.
EOF
