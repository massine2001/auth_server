#!/usr/bin/env bash
set -euo pipefail

CRT_PARAM="${CF_ORIGIN_CRT_PARAM:-/massine/auth/cf_origin_crt}"
KEY_PARAM="${CF_ORIGIN_KEY_PARAM:-/massine/auth/cf_origin_key}"
AWS_REGION="${AWS_REGION:-eu-north-1}"

CRT_PATH="/etc/pki/tls/certs/cloudflare-origin.crt"
KEY_PATH="/etc/pki/tls/private/cloudflare-origin.key"

sudo mkdir -p /etc/pki/tls/certs /etc/pki/tls/private

CRT_VALUE=$(aws ssm get-parameter --name "$CRT_PARAM" --with-decryption --query "Parameter.Value" --output text --region "$AWS_REGION")
KEY_VALUE=$(aws ssm get-parameter --name "$KEY_PARAM" --with-decryption --query "Parameter.Value" --output text --region "$AWS_REGION")

echo "$CRT_VALUE" | sudo tee "$CRT_PATH" >/dev/null
echo "$KEY_VALUE" | sudo tee "$KEY_PATH" >/dev/null
sudo chmod 600 "$KEY_PATH"
sudo chown root:root "$CRT_PATH" "$KEY_PATH"