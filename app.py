#!/usr/bin/env python3
import os

import aws_cdk as cdk

from lib.file_processing_cdk_stack import FileProcessingCdkStack


app = cdk.App()
FileProcessingCdkStack(app, "FileProcessingStack")

app.synth()
