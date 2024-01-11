
# How to run AWS experiments

## Prerequistes

- AWS account
- AWS Cli installed
- Terraform installed

Commands for devcontainer
```
sudo apt install unzip
curl -LO https://releases.hashicorp.com/terraform/1.6.6/terraform_1.6.6_linux_amd64.zip && unzip terraform_1.6.6_linux_amd64.zip && sudo mv terraform /usr/local/bin/ && rm terraform_1.6.6_linux_amd64.zip
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

## Upload test binary to s3

The test binay (that runs the p2p) is uploaded to s3. Running the bazel command will build it and upload it to s3. It requires aws credentials either explicitly or through any other accepted authentication method.

```
export AWS_ACCESS_KEY_ID=….
export AWS_SECRET_ACCESS_KEY=...
bazel run //rs/p2p/consensus_manager:aws
```

## Run p2p experiment

First the terraform file needs to be generated. The number after the file specifies the number of regions to use. It will pick the first n specified in `terraform-region-generator.py`. The second number is message size and the thirst is message rate.

```
python3 terraform-region-generator.py 3 100 10
```

After generating the terraform it can be applied

```
terraform apply -parallelism=30
```

It will keep running until you stop the experiment with

```
terraform destory
```



## Aws Instructions

(inside dev container)

Install saml2aws
```
CURRENT_VERSION=$(curl -Ls https://api.github.com/repos/Versent/saml2aws/releases/latest | grep 'tag_name' | cut -d'v' -f2 | cut -d'"' -f1)
curl -L -C - "https://github.com/Versent/saml2aws/releases/download/v${CURRENT_VERSION}/saml2aws_${CURRENT_VERSION}_linux_amd64.tar.gz" | tar -xzv -C /ic/bin
chmod u+x /ic/bin
hash -r
saml2aws --version

export SAML2AWS_DUO_MFA_OPTION="Duo Push"

echo "[ic-backups]
aws_profile             = ic-backups
role_arn                = arn:aws:iam::224267238713:role/DevOps
url                     = https://dfinity.okta.com/home/amazon_aws/0oaakgpu6dUVPYM9y357/272
username                = tim.gretler@dfinity.org
provider                = Okta
mfa                     = DUO
skip_verify             = false
aws_urn                 = urn:amazon:webservices
aws_session_duration    = 43200
saml_cache              = true
saml_cache_file         = /tmp/saml2aws/cache
disable_remember_device = false
disable_sessions        = false" > /tmp/saml2aws_conf

saml2aws -r eu-central-2 --config /tmp/saml2aws_conf login -a ic-backups
eval $(saml2aws --config /tmp/saml2aws_conf script -a ic-backups)
```
