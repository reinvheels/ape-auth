import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as docker_build from "@pulumi/docker-build";

const config = new pulumi.Config("ape-auth");
const domainName = config.require("domainName");

// Find Route53 hosted zone by recursively searching domain parts
async function findHostedZone(domain: string): Promise<aws.route53.GetZoneResult> {
  const parts = domain.split(".");
  for (let i = 0; i < parts.length - 1; i++) {
    const zoneName = parts.slice(i).join(".");
    try {
      return await aws.route53.getZone({ name: zoneName });
    } catch {
      continue;
    }
  }
  throw new Error(`No Route53 hosted zone found for domain "${domain}"`);
}

const hostedZone = findHostedZone(domainName);

const current = aws.getAvailabilityZones({ state: "available" });
const az = current.then((azs) => azs.names[0]);

// --- VPC (single-AZ, private only) ---

const vpc = new aws.ec2.Vpc("vpc", {
  cidrBlock: "10.0.0.0/16",
  enableDnsSupport: true,
  enableDnsHostnames: true,
});

const privateSubnet = new aws.ec2.Subnet("private-subnet", {
  vpcId: vpc.id,
  cidrBlock: "10.0.1.0/24",
  availabilityZone: az,
});

// --- Security Groups ---

const lambdaSg = new aws.ec2.SecurityGroup("lambda-sg", {
  vpcId: vpc.id,
  description: "Lambda security group",
  egress: [{ protocol: "-1", fromPort: 0, toPort: 0, cidrBlocks: ["0.0.0.0/0"] }],
});

const efsSg = new aws.ec2.SecurityGroup("efs-sg", {
  vpcId: vpc.id,
  description: "EFS security group",
  ingress: [
    {
      protocol: "tcp",
      fromPort: 2049,
      toPort: 2049,
      securityGroups: [lambdaSg.id],
    },
  ],
});

// --- EFS (One Zone, Elastic throughput) ---

const fs = new aws.efs.FileSystem("data", {
  availabilityZoneName: az,
  encrypted: true,
  throughputMode: "elastic",
  lifecyclePolicies: [{ transitionToIa: "AFTER_30_DAYS" }],
});

const mountTarget = new aws.efs.MountTarget("mount-target", {
  fileSystemId: fs.id,
  subnetId: privateSubnet.id,
  securityGroups: [efsSg.id],
});

const accessPoint = new aws.efs.AccessPoint("access-point", {
  fileSystemId: fs.id,
  posixUser: { uid: 1000, gid: 1000 },
  rootDirectory: {
    path: "/ape-auth",
    creationInfo: { ownerUid: 1000, ownerGid: 1000, permissions: "755" },
  },
});

// --- ECR + Docker Image ---

const repo = new aws.ecr.Repository("ape-auth", {
  forceDelete: true,
  imageTagMutability: "MUTABLE",
});

const token = aws.ecr.getAuthorizationTokenOutput({
  registryId: repo.registryId,
});

const image = new docker_build.Image("ape-auth-image", {
  tags: [pulumi.interpolate`${repo.repositoryUrl}:latest`],
  context: { location: "../auth" },
  platforms: ["linux/arm64"],
  push: true,
  registries: [
    {
      address: repo.repositoryUrl,
      username: token.userName,
      password: token.password,
    },
  ],
});

// --- Lambda ---

const role = new aws.iam.Role("lambda-role", {
  assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
    Service: "lambda.amazonaws.com",
  }),
});

new aws.iam.RolePolicyAttachment("lambda-vpc-policy", {
  role: role.name,
  policyArn: aws.iam.ManagedPolicies.AWSLambdaVPCAccessExecutionRole,
});

const efsMountPath = "/mnt/efs";
const efsDataDir = efsMountPath;

const fn = new aws.lambda.Function("ape-auth", {
  packageType: "Image",
  imageUri: image.ref.apply((ref) => {
    // docker-build returns "repo:tag@sha256:..." but Lambda only accepts "repo@sha256:..." or "repo:tag"
    const atIndex = ref.indexOf("@");
    if (atIndex === -1) return ref;
    const repo = ref.substring(0, ref.indexOf(":"));
    const digest = ref.substring(atIndex);
    return `${repo}${digest}`;
  }),
  architectures: ["arm64"],
  role: role.arn,
  memorySize: 256,
  timeout: 30,
  environment: {
    variables: {
      APE_AUTH_DATA_DIR: efsDataDir,
      APE_AUTH_PORT: "8080",
      APE_AUTH_ISSUER: `https://${domainName}`,
    },
  },
  vpcConfig: {
    subnetIds: [privateSubnet.id],
    securityGroupIds: [lambdaSg.id],
  },
  fileSystemConfig: {
    arn: accessPoint.arn,
    localMountPath: efsMountPath,
  },
}, { dependsOn: [mountTarget] });

// --- API Gateway ---

const api = new aws.apigatewayv2.Api("api", {
  protocolType: "HTTP",
});

const integration = new aws.apigatewayv2.Integration("lambda-integration", {
  apiId: api.id,
  integrationType: "AWS_PROXY",
  integrationUri: fn.invokeArn,
  payloadFormatVersion: "2.0",
});

const route = new aws.apigatewayv2.Route("default-route", {
  apiId: api.id,
  routeKey: "$default",
  target: pulumi.interpolate`integrations/${integration.id}`,
});

const stage = new aws.apigatewayv2.Stage("default-stage", {
  apiId: api.id,
  name: "$default",
  autoDeploy: true,
});

new aws.lambda.Permission("api-gw-permission", {
  action: "lambda:InvokeFunction",
  function: fn.name,
  principal: "apigateway.amazonaws.com",
  sourceArn: pulumi.interpolate`${api.executionArn}/*/*`,
});

// --- Custom Domain (ACM + Route53) ---

const cert = new aws.acm.Certificate("cert", {
  domainName,
  validationMethod: "DNS",
});

const certValidation = new aws.route53.Record("cert-validation", {
  zoneId: pulumi.output(hostedZone).apply((z) => z.zoneId),
  name: cert.domainValidationOptions[0].resourceRecordName,
  type: cert.domainValidationOptions[0].resourceRecordType,
  records: [cert.domainValidationOptions[0].resourceRecordValue],
  ttl: 300,
});

const certWait = new aws.acm.CertificateValidation("cert-wait", {
  certificateArn: cert.arn,
  validationRecordFqdns: [certValidation.fqdn],
});

const customDomain = new aws.apigatewayv2.DomainName("custom-domain", {
  domainName,
  domainNameConfiguration: {
    certificateArn: certWait.certificateArn,
    endpointType: "REGIONAL",
    securityPolicy: "TLS_1_2",
  },
});

new aws.apigatewayv2.ApiMapping("api-mapping", {
  apiId: api.id,
  domainName: customDomain.domainName,
  stage: stage.id,
});

new aws.route53.Record("api-dns", {
  zoneId: pulumi.output(hostedZone).apply((z) => z.zoneId),
  name: domainName,
  type: "A",
  aliases: [
    {
      name: customDomain.domainNameConfiguration.apply((c) => c.targetDomainName),
      zoneId: customDomain.domainNameConfiguration.apply((c) => c.hostedZoneId),
      evaluateTargetHealth: false,
    },
  ],
});

// --- Outputs ---

export const url = `https://${domainName}`;
export const apiEndpoint = api.apiEndpoint;
export const fileSystemId = fs.id;
export const vpcId = vpc.id;
