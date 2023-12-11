#!/bin/bash
set -e

PYTHON_VERSION=3.9.18

# Replace old OpenSSL and add build utilities
sudo yum -y remove openssl-devel* && \
sudo yum -y install gcc openssl11-devel bzip2-devel libffi-devel tar gzip wget make expat-devel

# Install Python
wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz
tar xzvf Python-${PYTHON_VERSION}.tgz
cd Python-${PYTHON_VERSION}

# We aim for similar `CONFIG_ARGS` that AL2 Python is built with
./configure --enable-loadable-sqlite-extensions --with-dtrace --with-lto --enable-optimizations --with-system-expat \
    --prefix=/usr/local/python${PYTHON_VERSION}

# Install into /usr/local/python3.9.x
# Note that "make install" links /usr/local/python3.9.3/bin/python3 while "altinstall" does not
sudo make altinstall

# Good practice to upgrade pip
sudo /usr/local/python${PYTHON_VERSION}/bin/python3.9 -m pip install --upgrade pip

# You could also install additional job-specific libraries in the bootstrap
# /usr/local/python${PYTHON_VERSION}/bin/python3.9 -m pip install pyarrow==12.0.0
#sudo /usr/local/python${PYTHON_VERSION}/bin/python3.9 -m pip install datasets transformers pinecone-client torch 
sudo /usr/local/python${PYTHON_VERSION}/bin/python3.9 -m pip install pyspark-ai
sudo /usr/local/python${PYTHON_VERSION}/bin/pip3.9 show pyspark-ai

sudo /usr/local/python${PYTHON_VERSION}/bin/python3.9 -m pip install "boto3>=1.28.62" "botocore>=1.31.57" "langchain>=0.0.309"

#sudo /usr/local/python${PYTHON_VERSION}/bin/python3.9 -m pip --no-build-isolation --force-reinstall "boto3>=1.28.62" "awscli>=1.29.57" "botocore>=1.31.57" langchain==0.0.309

#curl https://d2eo22ngex1n9g.cloudfront.net/Documentation/SDK/bedrock-python-sdk.zip --output bedrock-python-sdk.zip

#unzip bedrock-python-sdk.zip -d bedrock-python-sdk
#cd bedrock-python-sdk

#sudo /usr/local/python${PYTHON_VERSION}/bin/python3.9 -m pip install botocore-*-py3-none-any.whl
#sudo /usr/local/python${PYTHON_VERSION}/bin/python3.9 -m pip install boto3-*-py3-none-any.whl