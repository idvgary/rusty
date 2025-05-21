import { App } from "aws-cdk-lib";
import { GithubOidcStack } from "../lib/stacks/github-oidc";
import { ObservabilityForwarderStack } from "../lib/stacks/observability-forwarder";

const accountId = "337584429991";
const region = process.env.AWS_REGION;

if (!region) {
  throw new Error(
    "AWS_REGION environment variable is not set. Please set it to the target AWS region."
  );
}

const app = new App();

new GithubOidcStack(app, "GithubOidcStack", {
  env: {
    account: accountId,
    region: region,
  },
});
new ObservabilityForwarderStack(app, "ObservabilityForwarderStack", {
  env: {
    account: accountId,
    region: region,
  },
});
