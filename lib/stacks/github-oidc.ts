import { CfnOutput, Stack, StackProps } from "aws-cdk-lib";
import {
  Conditions,
  Effect,
  OpenIdConnectProvider,
  PolicyDocument,
  PolicyStatement,
  Role,
  WebIdentityPrincipal,
} from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";

export class GithubOidcStack extends Stack {
  public readonly githubActionsRole: Role;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const githubOidcProvider = new OpenIdConnectProvider(this, "GitHubOidcProvider", {
      url: "https://token.actions.githubusercontent.com",
      clientIds: ["sts.amazonaws.com"],
    });

    const githubDeployConditions: Conditions = {
      StringEquals: {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      },
      StringLike: {
        "token.actions.githubusercontent.com:sub":
          "repo:idvhq/observability-forwarder:environment:*",
      },
    };

    this.githubActionsRole = new Role(this, "GithubActionsRole", {
      roleName: "GitHubActionsRole",
      assumedBy: new WebIdentityPrincipal(
        githubOidcProvider.openIdConnectProviderArn,
        githubDeployConditions,
      ),
      inlinePolicies: {
        AssumeCdkRoles: new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ["sts:AssumeRole"],
              resources: [`arn:aws:iam::${this.account}:role/cdk-*`],
            }),
          ],
        }),
      },
    });

    new CfnOutput(this, "GithubActionsRoleArn", {
      exportName: "GithubActionsRoleArn",
      value: this.githubActionsRole.roleArn,
    });
  }
}
