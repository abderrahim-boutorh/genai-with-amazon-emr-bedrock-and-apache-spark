# Use generative AI with Amazon EMR, Amazon Bedrock, and English SDK for Apache Spark to unlock insights

## Introduction
In the age of big data, organisations globally are always looking for creative approaches to derive value and insights from their extensive datasets. In a previous [article](https://medium.com/@boutorh.abderrahim/explore-your-data-lake-using-amazon-athena-for-apache-spark-e0dfa05f01c6), we explored how data analysts can analyse petabytes of data by harnessing the power of Apache Spark on [Amazon Athena](https://aws.amazon.com/athena/). In this article, we take it a step further to discover how to enhance your data analytics using generative AI with [Amazon EMR](https://aws.amazon.com/emr/), [Amazon Bedrock](https://aws.amazon.com/blogs/big-data/category/artificial-intelligence/amazon-machine-learning/amazon-bedrock/), and the [pyspark-ai](https://github.com/pyspark-ai/pyspark-ai) library. 

The [pyspark-ai](https://github.com/pyspark-ai/pyspark-ai) library serves as an English SDK for Apache Spark, interpreting instructions in English and translating them into PySpark objects such as DataFrames. This simplifies Spark usage, enabling you to concentrate on extracting value from your data effortlessly.

The goal of this guide is to provide you with the instructions for implementing the infrastructure needed to successfully deploy and run data analytics jobs on a Jupyter notebook within an EMR cluster.

This tutorial is derived from this [blog]() post. Follow the blog to complete the tutorial.


## Prerequisites
To make the most of this tutorial, ensure you have the following:

- An AWS account and an IAM User with permissions to create an IAM role and IAM policies.
- The Titan Text G1 – Express model is currently in preview, so you need to have preview access to use it as part of this post.
- Terraform CLI installed locally and basic understanding of terraform templates.
- Basic understanding of Apache Spark.

I strongly recommend checking out the Terraform template provided. It will help you better understand how all the different parts of the infrastructure are set up and connected.

## Quick Start
To quickly run this tutorial, run the following commands:
```
terraform init
terraform apply
```
