from aws_cdk import (
    Stack,
    aws_lambda as lambda_,
    aws_lambda_python_alpha as lambda_python,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
    aws_s3 as s3,
    aws_iam as iam,
    aws_events as events,
    aws_events_targets as targets,
    Duration,
    CfnOutput,
    RemovalPolicy,
)
from constructs import Construct


class FileProcessingCdkStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # S3 Bucket
        bucket = s3.Bucket(
            self,
            "FileProcessingBucket",
            bucket_name="file-processing-bucket-1234567890",
            removal_policy=RemovalPolicy.DESTROY,
            event_bridge_enabled=True,
        )

        # Lambda layer
        file_processing_layer = lambda_python.PythonLayerVersion(
            self,
            "FileProcessingLambdaLayer",
            entry="lib/layer",
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_12],
            layer_version_name="FileProcessingLambdaLayer",
        )

        # IAM Role for Lambda
        lambda_role = iam.Role(
            self,
            "LambdaExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="FileProcessingLambdaRole",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
            ],
        )

        # Add S3 read permissions to the role
        bucket.grant_read(lambda_role)

        # Lambda Functions using Python 3.12
        validate_function = lambda_python.PythonFunction(
            self,
            "ValidateFileFunction",
            function_name="ValidateFileFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            entry="lambdas",
            index="validate.py",
            handler="handler",
            role=lambda_role,
            layers=[file_processing_layer],
        )

        process_function = lambda_python.PythonFunction(
            self,
            "ProcessFileFunction",
            function_name="ProcessFileFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            entry="lambdas",
            index="process.py",
            handler="handler",
            role=lambda_role,
        )

        email_function = lambda_python.PythonFunction(
            self,
            "SendEmailFunction",
            function_name="SendEmailFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            entry="lambdas",
            index="send_email.py",
            handler="handler",
            role=lambda_role,
        )

        # Step functions Definition
        validate_task = tasks.LambdaInvoke(
            self, "Validate File", lambda_function=validate_function
        )

        process_task = tasks.LambdaInvoke(
            self, "Process File", lambda_function=process_function
        )

        email_task = tasks.LambdaInvoke(
            self, "Send Email", lambda_function=email_function
        )

        chain = validate_task.next(
            sfn.Choice(self, "ValidateFile?")
            .when(
                sfn.Condition.boolean_equals("$.Payload.valid", True),
                process_task.next(email_task),
            )
            .otherwise(email_task)
        )

        # Step Function
        state_machine = sfn.StateMachine(
            self,
            "FileProcessingStateMachine",
            state_machine_name="FileProcessingStateMachine",
            definition=chain,
            timeout=Duration.minutes(5),
        )

        # EventBridge Rule
        rule = events.Rule(
            self,
            "S3ToStepFunctionRule",
            event_pattern=events.EventPattern(
                source=["aws.s3"],
                detail_type=["Object Created"],
                detail={
                    "bucket": {"name": [bucket.bucket_name]},
                    "object": {"key": [{"prefix": ""}]},
                },
            ),
        )

        # Set the Step Function as the target of the EventBridge rule
        rule.add_target(targets.SfnStateMachine(state_machine))

        CfnOutput(self, "BucketName", value=bucket.bucket_name)
        CfnOutput(self, "StateMachineArn", value=state_machine.state_machine_arn)
