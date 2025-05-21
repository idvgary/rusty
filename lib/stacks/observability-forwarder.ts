import { join } from "node:path";
import { CfnOutput, Duration, RemovalPolicy, Stack, StackProps } from "aws-cdk-lib";
import {
  Effect,
  PolicyDocument,
  PolicyStatement,
  Role,
  ServicePrincipal,
} from "aws-cdk-lib/aws-iam";
import { Stream, StreamMode } from "aws-cdk-lib/aws-kinesis";
import {
  ApplicationLogLevel,
  Architecture,
  Code,
  Function,
  LayerVersion,
  LoggingFormat,
  Runtime,
  StartingPosition,
  SystemLogLevel,
} from "aws-cdk-lib/aws-lambda";
import { KinesisEventSource } from "aws-cdk-lib/aws-lambda-event-sources";
import { CfnDestination } from "aws-cdk-lib/aws-logs";
import { Secret } from "aws-cdk-lib/aws-secretsmanager";
import type { Construct } from "constructs";

export class ObservabilityForwarderStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps = {}) {
    super(scope, id, props);

    //==============================================================================
    // OTLP FORWARDER (LAMBDA)
    //==============================================================================

    const rotelCollectorLayer = LayerVersion.fromLayerVersionArn(
      this,
      "RotelCollectorLayer",
      `arn:aws:lambda:${this.region}:418653438961:layer:rotel-extension-arm64-alpha:23`,
    );

    const rotelChConfig = Secret.fromSecretCompleteArn(
      this,
      "RotelChConfig",
      `arn:aws:secretsmanager:${this.region}:${this.account}:secret:rotel-ch-config-RxZMnb`,
    );

    const otlpChForwarder = new Function(this, "OtlpChForwarder", {
      runtime: Runtime.PROVIDED_AL2023,
      handler: "bootstrap",
      code: Code.fromAsset(join(__dirname, "../../target/lambda/otlp-ch-forwarder")),
      architecture: Architecture.ARM_64,
      memorySize: 2048,
      timeout: Duration.minutes(1),
      loggingFormat: LoggingFormat.JSON,
      systemLogLevelV2: SystemLogLevel.WARN,
      applicationLogLevelV2: ApplicationLogLevel.INFO,
      layers: [rotelCollectorLayer],
      environment: {
        // Lambda OTel Lite
        LAMBDA_EXTENSION_SPAN_PROCESSOR_MODE: "async",
        LAMBDA_TRACING_ENABLE_FMT_LAYER: "true",
        // OTel SDK
        OTEL_EXPORTER_OTLP_ENDPOINT: "http://localhost:4318",
        OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf",
        // ROTel Collector (Lambda Extension)
        ROTEL_EXPORTER: "clickhouse",
        ROTEL_CLICKHOUSE_EXPORTER_ENDPOINT: "${" + rotelChConfig.secretArn + "#endpoint}",
        ROTEL_CLICKHOUSE_EXPORTER_DATABASE: "${" + rotelChConfig.secretArn + "#database}",
        ROTEL_CLICKHOUSE_EXPORTER_USER: "${" + rotelChConfig.secretArn + "#user}",
        ROTEL_CLICKHOUSE_EXPORTER_PASSWORD: "${" + rotelChConfig.secretArn + "#password}",
      },
    });
    otlpChForwarder.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ["secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue"],
        resources: ["*"],
      }),
    );

    //==============================================================================
    // OTLP TRANSPORT (KINESIS)
    //==============================================================================

    // Create a Kinesis stream for OTel traces
    const otlpStream = new Stream(this, "OtlpStream", {
      streamMode: StreamMode.ON_DEMAND,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Grant CloudWatch Logs write permissions to the Kinesis stream
    const cwlToKinesisRole = new Role(this, "CwlToKinesisRole", {
      assumedBy: new ServicePrincipal("logs.amazonaws.com"),
      inlinePolicies: {
        KinesisWritePolicy: new PolicyDocument({
          statements: [
            new PolicyStatement({
              actions: ["kinesis:PutRecord"],
              resources: [otlpStream.streamArn],
              effect: Effect.ALLOW,
            }),
          ],
        }),
      },
    });

    // Create the CloudWatch Logs Destination
    const otlpStreamDestination = new CfnDestination(this, "OtlpStreamDestination", {
      destinationName: "OtlpStreamDestination",
      targetArn: otlpStream.streamArn,
      roleArn: cwlToKinesisRole.roleArn,
      destinationPolicy: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Principal: "*",
            Action: ["logs:PutSubscriptionFilter", "logs:PutAccountPolicy"],
            Resource: `arn:aws:logs:${this.region}:${this.account}:destination:OtlpStreamDestination`,
            Condition: {
              StringEquals: {
                "aws:PrincipalOrgID": ["o-3d6yd62p13", "o-z1w4f8rn2t"],
              },
            },
          },
        ],
      }),
    });

    // Add Kinesis as an event source for the OTLP Forwarder
    otlpChForwarder.addEventSource(
      new KinesisEventSource(otlpStream, {
        startingPosition: StartingPosition.LATEST,
        batchSize: 10000,
        maxBatchingWindow: Duration.seconds(1),
        parallelizationFactor: 1,
        reportBatchItemFailures: false,
        bisectBatchOnError: false,
      }),
    );

    //==============================================================================
    // CFN OUTPUTS
    //==============================================================================

    new CfnOutput(this, "LogDestinationArn", {
      value: otlpStreamDestination.attrArn,
      description: "ARN of the CloudWatch Logs Destination for cross-account subscriptions",
    });
  }
}
