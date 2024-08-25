from aws_cdk import (
    Stack,
    aws_s3 as s3,
    aws_lambda as lambda_,
    aws_lambda_python_alpha as lambda_python,
    aws_s3_notifications as s3n,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
    aws_iam as iam,
    CfnOutput, Duration, RemovalPolicy
)
from constructs import Construct


class FileProcessingCdkStack(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # S3 Bucket
        bucket = s3.Bucket(self, "FileProcessingBucket",
                           bucket_name="file-processing-bucket-1234567890",
                           removal_policy=RemovalPolicy.DESTROY)

        # Lambda layer
        file_processing_layer = lambda_python.PythonLayerVersion(self, "FileProcessingLambdaLayer",
                                                                 entry="lib/layer",
                                                                 compatible_runtimes=[lambda_.Runtime.PYTHON_3_12],
                                                                 layer_version_name="FileProcessingLambdaLayer")

        # IAM Role for Lambda
        lambda_role = iam.Role(self, "LambdaExecutionRole",
                               assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                               managed_policies=[
                                   iam.ManagedPolicy.from_aws_managed_policy_name(
                                       "service-role/AWSLambdaBasicExecutionRole"),
                               ])

        # Add S3 read permissions to the role
        bucket.grant_read(lambda_role)

        # Lambda Functions using Python 3.12
        validate_function = lambda_python.PythonFunction(self, "ValidateFileFunction",
                                                         function_name="ValidateFileFunction",
                                                         runtime=lambda_.Runtime.PYTHON_3_12,
                                                         entry="lambdas",
                                                         index="validate.py",
                                                         handler="handler",
                                                         role=lambda_role,
                                                         layers=[file_processing_layer])

        process_function = lambda_python.PythonFunction(self, "ProcessFileFunction",
                                                        function_name="ProcessFileFunction",
                                                        runtime=lambda_.Runtime.PYTHON_3_12,
                                                        entry="lambdas",  # Directory with process.py
                                                        index="process.py",
                                                        handler="handler",
                                                        role=lambda_role)

        email_function = lambda_python.PythonFunction(self, "SendEmailFunction",
                                                      function_name="SendEmailFunction",
                                                      runtime=lambda_.Runtime.PYTHON_3_12,
                                                      entry="lambdas",  # Directory with send_email.py
                                                      index="send_email.py",
                                                      handler="handler",
                                                      role=lambda_role)

        # Step Functions Tasks
        validate_task = tasks.LambdaInvoke(self, "Validate File",
                                           lambda_function=validate_function,
                                           output_path="$.Payload")

        process_task = tasks.LambdaInvoke(self, "Process File",
                                          lambda_function=process_function,
                                          output_path="$.Payload")

        email_task = tasks.LambdaInvoke(self, "Send Email",
                                        lambda_function=email_function,
                                        output_path="$.Payload")

        # Step Functions Definition
        definition = validate_task.next(
            sfn.Choice(self, "File Valid?")
            .when(sfn.Condition.boolean_equals("$.valid", True), process_task.next(email_task))
            .otherwise(email_task)
        )

        # Step Function
        sm = sfn.StateMachine(self, "FileProcessingStateMachine",
                              definition=definition,
                              timeout=Duration.minutes(5))

        # S3 Event Notification to trigger the Step Function
        bucket.add_event_notification(s3.EventType.OBJECT_CREATED, s3n.LambdaDestination(validate_function))

        CfnOutput(self, "BucketName", value=bucket.bucket_name)
        CfnOutput(self, "StateMachineArn", value=sm.state_machine_arn)
