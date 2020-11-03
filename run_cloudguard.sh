#!/bin/bash
#export PATH=$PATH:$HOME/.bin
#tfswitch -b $HOME/.bin/terraform
#tgswitch -b $HOME/.bin/terragrunt

#cd /mnt/d/github/iam-terraform/applied/accounts/
echo "Enter MFA Token: "
read MFA_TOKEN
CREDJSON=$(aws sts get-session-token --serial-number arn:aws:iam::569715827492:mfa/jsimoni@ipipeline.com --profile default --token-code $MFA_TOKEN)
ACCESSKEY="$(echo $CREDJSON | jq '.Credentials.AccessKeyId' | sed 's/"//g')"
SECRETKEY="$(echo $CREDJSON | jq '.Credentials.SecretAccessKey' | sed 's/"//g')"
SESSIONTOKEN="$(echo $CREDJSON | jq '.Credentials.SessionToken' | sed 's/"//g')"

export AWS_ACCESS_KEY_ID=$ACCESSKEY
export AWS_SECRET_ACCESS_KEY=$SECRETKEY
export AWS_SESSION_TOKEN=$SESSIONTOKEN

eval $(awscredswrap --role-arn arn:aws:iam::569715827492:role/iammaster_role --role-session-name jsimoni-iammaster)

#wget -O cloudguard-readonly-policy.json https://raw.githubusercontent.com/ipipeline/iam-terraform/master/infrastructure/modules/iam_cloudguard_readonly/cloudguard-readonly-policy.json?token= cloudguard-readonly-policy.json

for account in $(aws organizations list-accounts | jq -r '.Accounts[] | select(.Status == "ACTIVE") | .Id')
do
  if [ $account == "657155003434" ]; then
  echo -e $account
    export AWS_ACCESS_KEY_ID=$ACCESSKEY
    export AWS_SECRET_ACCESS_KEY=$SECRETKEY
    export AWS_SESSION_TOKEN=$SESSIONTOKEN

    eval $(awscredswrap --role-arn arn:aws:iam::$account:role/iammaster_role --role-session-name jsimoni-iammaster)

    ACTION="createX"
    if [ $ACTION == "create" ]; then
      aws iam create-role --role-name cloudguard_connect_role --assume-role-policy-document file://trust-policy.json
      aws iam create-policy --policy-name CloudGuard-readonly-policy --policy-document file://cloudguard-readonly-policy.json
      aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/SecurityAudit --role-name cloudguard_connect_role
      aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonInspectorReadOnlyAccess --role-name cloudguard_connect_role
      aws iam attach-role-policy --policy-arn arn:aws:iam::$account:policy/CloudGuard-readonly-policy --role-name cloudguard_connect_role
    else
      aws iam detach-role-policy --policy-arn arn:aws:iam::aws:policy/SecurityAudit --role-name cloudguard_connect_role
      aws iam detach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonInspectorReadOnlyAccess --role-name cloudguard_connect_role
      aws iam detach-role-policy --policy-arn arn:aws:iam::$account:policy/CloudGuard-readonly-policy --role-name cloudguard_connect_role
      aws iam delete-policy --policy-arn arn:aws:iam::$account:policy/CloudGuard-readonly-policy
      aws iam delete-role --role-name cloudguard_connect_role
    fi
  fi
done
