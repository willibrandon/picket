"use strict";

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const supportedFormats = new Set(["json", "jsonl", "sarif", "html", "csv", "junit", "gitlab", "toon"]);
const supportedRulePacks = new Set(["picket-experimental", "picket-strict"]);
const reportExtensions = new Map([
  ["json", "json"],
  ["jsonl", "jsonl"],
  ["sarif", "sarif"],
  ["html", "html"],
  ["csv", "csv"],
  ["junit", "junit.xml"],
  ["gitlab", "gitlab.json"],
  ["toon", "toon"]
]);

if (require.main === module) {
  main();
}

function main() {
  try {
    const inputs = readInputs();
    fs.mkdirSync(inputs.reportDirectory, { recursive: true });

    const reportPaths = createReportPaths(inputs.reportDirectory, inputs.reportFormats);
    const args = createPicketArguments(inputs, reportPaths);
    const result = spawnSync(inputs.picketPath, args, {
      cwd: process.cwd(),
      env: process.env,
      stdio: "inherit",
      windowsHide: true
    });
    if (result.error) {
      throw result.error;
    }

    const exitCode = typeof result.status === "number" ? result.status : 1;
    const jsonlPath = reportPaths.get("jsonl") || "";
    const findings = countJsonLines(jsonlPath);
    const annotations = inputs.annotations ? emitAnnotations(jsonlPath, inputs.annotationLimit) : 0;

    setOutput("exitCode", String(exitCode));
    setOutput("findings", String(findings));
    setOutput("sarifPath", reportPaths.get("sarif") || "");
    setOutput("jsonlPath", jsonlPath);
    setOutput("htmlPath", reportPaths.get("html") || "");
    setOutput("annotations", String(annotations));

    publishReports(inputs, reportPaths);
    writeSummary(inputs, exitCode, findings, annotations, reportPaths);

    if (isScannerError(exitCode, findings)) {
      complete("Failed", "Picket scan failed before producing findings.");
      process.exit(1);
    }

    if (shouldFail(inputs.failOn, exitCode, findings)) {
      complete("Failed", `Picket scan failed with policy '${inputs.failOn}'.`);
      process.exit(1);
    }

    complete("Succeeded", "Picket scan completed.");
  }
  catch (error) {
    complete("Failed", error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}

function readInputs() {
  const target = getInput("target", process.env.BUILD_SOURCESDIRECTORY || ".");
  const reportFormats = parseList(getInput("reportFormats", "sarif,jsonl,html")).map(format => format.toLowerCase());
  if (reportFormats.length === 0) {
    throw new Error("reportFormats must include at least one report format.");
  }

  for (const format of reportFormats) {
    if (!supportedFormats.has(format)) {
      throw new Error(`Unsupported report format '${format}'.`);
    }
  }

  const failOn = getChoice("failOn", "findings", ["findings", "errors", "never"]);
  const rulePacks = [...new Set(parseList(getInput("rulePacks", "")).map(rulePack => rulePack.toLowerCase()))];
  for (const rulePack of rulePacks) {
    if (!supportedRulePacks.has(rulePack)) {
      throw new Error(`Unsupported built-in rule pack '${rulePack}'. Use picket-strict or picket-experimental.`);
    }
  }

  const results = getInput("results", "");
  const onlyVerified = getBoolean("onlyVerified", false);
  if (results.length !== 0 && onlyVerified) {
    throw new Error("results and onlyVerified cannot both be set.");
  }

  const redact = getInteger("redact", 100, 0, 100);
  const annotationLimit = getInteger("annotationLimit", 50, 0, Number.MAX_SAFE_INTEGER);
  const azureDevOpsIncludePackages = getBoolean("azureDevOpsIncludePackages", false);
  const azureDevOpsFeed = getInput("azureDevOpsFeed", "");
  const azureDevOpsPackage = getInput("azureDevOpsPackage", "");
  const azureDevOpsPackageVersion = getInput("azureDevOpsPackageVersion", "");
  const azureDevOpsMaxPackageMegabytes = getOptionalPositiveInteger("azureDevOpsMaxPackageMegabytes");
  if (!azureDevOpsIncludePackages && (azureDevOpsFeed || azureDevOpsPackage || azureDevOpsPackageVersion || azureDevOpsMaxPackageMegabytes)) {
    throw new Error("Azure Artifacts feed, package, and package limit settings require azureDevOpsIncludePackages.");
  }

  if (azureDevOpsPackageVersion && !azureDevOpsPackage) {
    throw new Error("azureDevOpsPackageVersion requires azureDevOpsPackage.");
  }

  return {
    target,
    picketPath: getInput("picketPath", "picket"),
    config: getOptionalFileInput("config", target),
    profile: getChoice("profile", "picket", ["picket", "gitleaks"]),
    rulePacks,
    reportFormats,
    reportDirectory: path.resolve(getInput("reportDirectory", defaultReportDirectory())),
    failOn,
    baselinePath: getOptionalFileInput("baselinePath", target),
    results,
    onlyVerified,
    redact,
    annotations: getBoolean("annotations", true),
    annotationLimit,
    publishSarif: getBoolean("publishSarif", true),
    publishJsonl: getBoolean("publishJsonl", true),
    publishHtml: getBoolean("publishHtml", true),
    cache: getBoolean("cache", true),
    cacheMode: getChoice("cacheMode", "secret-hash-only", ["secret-hash-only", "raw"]),
    cachePath: path.resolve(getInput("cachePath", defaultCachePath())),
    maxTargetMegabytes: getOptionalPositiveInteger("maxTargetMegabytes"),
    maxArchiveDepth: getOptionalNonNegativeInteger("maxArchiveDepth"),
    maxArchiveEntries: getOptionalNonNegativeInteger("maxArchiveEntries"),
    maxArchiveMegabytes: getOptionalNonNegativeInteger("maxArchiveMegabytes"),
    maxArchiveRatio: getOptionalNonNegativeInteger("maxArchiveRatio"),
    timeout: getOptionalNonNegativeInteger("timeout"),
    verify: getBoolean("verify", false),
    azureDevOpsOrganization: getInput("azureDevOpsOrganization", ""),
    azureDevOpsEndpoint: getInput("azureDevOpsEndpoint", ""),
    azureDevOpsTokenEnv: getInput("azureDevOpsTokenEnv", ""),
    azureDevOpsTokenKind: getChoice("azureDevOpsTokenKind", "pat", ["pat", "bearer"]),
    azureDevOpsProject: getInput("azureDevOpsProject", ""),
    azureDevOpsRepository: getInput("azureDevOpsRepository", ""),
    azureDevOpsBranch: getInput("azureDevOpsBranch", ""),
    azureDevOpsPullRequest: getOptionalPositiveInteger("azureDevOpsPullRequest"),
    azureDevOpsIncludeWikis: getBoolean("azureDevOpsIncludeWikis", false),
    azureDevOpsBuildId: getOptionalPositiveInteger("azureDevOpsBuildId"),
    azureDevOpsIncludeArtifacts: getBoolean("azureDevOpsIncludeArtifacts", false),
    azureDevOpsIncludeLogs: getBoolean("azureDevOpsIncludeLogs", false),
    azureDevOpsReleaseId: getOptionalPositiveInteger("azureDevOpsReleaseId"),
    azureDevOpsIncludeReleaseArtifacts: getBoolean("azureDevOpsIncludeReleaseArtifacts", false),
    azureDevOpsIncludePackages,
    azureDevOpsFeed,
    azureDevOpsPackage,
    azureDevOpsPackageVersion,
    azureDevOpsMaxArtifactMegabytes: getOptionalPositiveInteger("azureDevOpsMaxArtifactMegabytes"),
    azureDevOpsMaxLogMegabytes: getOptionalPositiveInteger("azureDevOpsMaxLogMegabytes"),
    azureDevOpsMaxPackageMegabytes,
    allowNonPublicSourceEndpoints: getBoolean("allowNonPublicSourceEndpoints", false),
    allowInsecureSourceEndpoints: getBoolean("allowInsecureSourceEndpoints", false),
    extraArgs: splitExtraArgs(getInput("extraArgs", ""))
  };
}

function createReportPaths(reportDirectory, formats) {
  const taskFormats = formats.includes("jsonl") ? formats : [...formats, "jsonl"];
  const paths = new Map();
  for (const format of taskFormats) {
    paths.set(format, path.join(reportDirectory, `picket.${reportExtensions.get(format)}`));
  }

  return paths;
}

function createPicketArguments(inputs, reportPaths) {
  const args = ["scan", inputs.target, "--profile", inputs.profile, `--redact=${inputs.redact}`];

  addValue(args, "--config", inputs.config);
  addValue(args, "--baseline-path", inputs.baselinePath);
  for (const rulePack of inputs.rulePacks) {
    addValue(args, "--rule-pack", rulePack);
  }

  for (const reportPath of reportPaths.values()) {
    addValue(args, "--report-path", reportPath);
  }

  if (inputs.cache) {
    addValue(args, "--cache-dir", inputs.cachePath);
    addValue(args, "--cache-mode", inputs.cacheMode);
  }

  if (inputs.onlyVerified) {
    args.push("--only-verified");
  }

  if (inputs.verify) {
    args.push("--verify");
  }

  addValue(args, "--results", inputs.results);
  addValue(args, "--max-target-megabytes", inputs.maxTargetMegabytes);
  addValue(args, "--max-archive-depth", inputs.maxArchiveDepth);
  addValue(args, "--max-archive-entries", inputs.maxArchiveEntries);
  addValue(args, "--max-archive-megabytes", inputs.maxArchiveMegabytes);
  addValue(args, "--max-archive-ratio", inputs.maxArchiveRatio);
  addValue(args, "--timeout", inputs.timeout);

  addValue(args, "--azure-devops-organization", inputs.azureDevOpsOrganization);
  addValue(args, "--azure-devops-endpoint", inputs.azureDevOpsEndpoint);
  addValue(args, "--azure-devops-token-env", inputs.azureDevOpsTokenEnv);
  if (inputs.azureDevOpsOrganization || inputs.azureDevOpsEndpoint) {
    addValue(args, "--azure-devops-token-kind", inputs.azureDevOpsTokenKind);
  }

  addValue(args, "--azure-devops-project", inputs.azureDevOpsProject);
  addValue(args, "--azure-devops-repository", inputs.azureDevOpsRepository);
  addValue(args, "--azure-devops-branch", inputs.azureDevOpsBranch);
  addValue(args, "--azure-devops-pull-request", inputs.azureDevOpsPullRequest);
  addValue(args, "--azure-devops-build-id", inputs.azureDevOpsBuildId);
  addValue(args, "--azure-devops-release-id", inputs.azureDevOpsReleaseId);
  addValue(args, "--azure-devops-feed", inputs.azureDevOpsFeed);
  addValue(args, "--azure-devops-package", inputs.azureDevOpsPackage);
  addValue(args, "--azure-devops-package-version", inputs.azureDevOpsPackageVersion);
  addValue(args, "--azure-devops-max-artifact-megabytes", inputs.azureDevOpsMaxArtifactMegabytes);
  addValue(args, "--azure-devops-max-log-megabytes", inputs.azureDevOpsMaxLogMegabytes);
  addValue(args, "--azure-devops-max-package-megabytes", inputs.azureDevOpsMaxPackageMegabytes);
  addFlag(args, "--azure-devops-include-wikis", inputs.azureDevOpsIncludeWikis);
  addFlag(args, "--azure-devops-include-artifacts", inputs.azureDevOpsIncludeArtifacts);
  addFlag(args, "--azure-devops-include-logs", inputs.azureDevOpsIncludeLogs);
  addFlag(args, "--azure-devops-include-release-artifacts", inputs.azureDevOpsIncludeReleaseArtifacts);
  addFlag(args, "--azure-devops-include-packages", inputs.azureDevOpsIncludePackages);
  addFlag(args, "--allow-non-public-source-endpoints", inputs.allowNonPublicSourceEndpoints);
  addFlag(args, "--allow-insecure-source-endpoints", inputs.allowInsecureSourceEndpoints);

  args.push(...inputs.extraArgs);
  return args;
}

function addValue(args, name, value) {
  if (value !== undefined && value !== null && String(value).length !== 0) {
    args.push(name, String(value));
  }
}

function addFlag(args, name, enabled) {
  if (enabled) {
    args.push(name);
  }
}

function countJsonLines(jsonlPath) {
  if (!jsonlPath || !fs.existsSync(jsonlPath)) {
    return 0;
  }

  const content = fs.readFileSync(jsonlPath, "utf8").trim();
  if (content.length === 0) {
    return 0;
  }

  return content.split(/\r?\n/).filter(line => line.trim().length !== 0).length;
}

function emitAnnotations(jsonlPath, limit) {
  if (!jsonlPath || limit === 0 || !fs.existsSync(jsonlPath)) {
    return 0;
  }

  const lines = fs.readFileSync(jsonlPath, "utf8").split(/\r?\n/);
  let emitted = 0;
  for (const line of lines) {
    if (emitted >= limit || line.trim().length === 0) {
      continue;
    }

    let finding;
    try {
      finding = JSON.parse(line);
    }
    catch {
      continue;
    }

    const file = toSafeText(finding.file);
    const ruleId = toSafeText(finding.ruleId);
    const startLine = Number.isInteger(finding.startLine) && finding.startLine > 0 ? finding.startLine : 1;
    const message = `Picket finding ${ruleId || "unknown-rule"}`;
    console.log(`##vso[task.logissue type=warning;sourcepath=${escapeProperty(file)};linenumber=${startLine};]${escapeMessage(message)}`);
    emitted++;
  }

  return emitted;
}

function publishReports(inputs, reportPaths) {
  publishReport(inputs.publishSarif, "picket-sarif", reportPaths.get("sarif"));
  publishReport(inputs.publishJsonl, "picket-jsonl", reportPaths.get("jsonl"));
  publishReport(inputs.publishHtml, "picket-html", reportPaths.get("html"));
}

function publishReport(enabled, artifactName, reportPath) {
  if (!enabled || !reportPath || !fs.existsSync(reportPath)) {
    return;
  }

  console.log(`##vso[artifact.upload artifactname=${escapeProperty(artifactName)};]${escapeMessage(reportPath)}`);
}

function writeSummary(inputs, exitCode, findings, annotations, reportPaths) {
  const lines = [
    "# Picket scan",
    "",
    `Scanner exit code: ${exitCode}`,
    `Findings: ${findings}`,
    `Annotations: ${annotations}`,
    `Fail on: ${inputs.failOn}`,
    "",
    "Reports:"
  ];

  for (const [format, reportPath] of reportPaths) {
    lines.push(`- ${format}: ${reportPath}`);
  }

  console.log(lines.join("\n"));
}

function shouldFail(failOn, exitCode, findings) {
  if (failOn === "findings") {
    return findings > 0;
  }

  return false;
}

function isScannerError(exitCode, findings) {
  return exitCode === 2 || (exitCode !== 0 && findings === 0);
}

function setOutput(name, value) {
  console.log(`##vso[task.setvariable variable=${escapeProperty(name)};isOutput=true;]${escapeMessage(value)}`);
}

function complete(result, message) {
  console.log(`##vso[task.complete result=${result};]${escapeMessage(message)}`);
}

function getInput(name, fallback) {
  const value = process.env[`INPUT_${name}`]
    ?? process.env[`INPUT_${name.toUpperCase()}`]
    ?? process.env[`INPUT_${toInputEnvironmentName(name)}`];
  if (value === undefined || value.trim().length === 0) {
    return fallback;
  }

  return value.trim();
}

function getOptionalFileInput(name, defaultDirectory) {
  const value = getInput(name, "");
  if (value.length === 0) {
    return "";
  }

  if (isDefaultInputDirectory(value, defaultDirectory)) {
    return "";
  }

  return value;
}

function isDefaultInputDirectory(value, defaultDirectory) {
  if (!isDirectory(value)) {
    return false;
  }

  return pathEquals(value, defaultDirectory)
    || pathEquals(value, process.env.BUILD_SOURCESDIRECTORY || "");
}

function getBoolean(name, fallback) {
  const value = getInput(name, fallback ? "true" : "false").toLowerCase();
  if (value === "true") {
    return true;
  }

  if (value === "false") {
    return false;
  }

  throw new Error(`${name} must be true or false.`);
}

function getChoice(name, fallback, choices) {
  const value = getInput(name, fallback).toLowerCase();
  if (!choices.includes(value)) {
    throw new Error(`${name} must be one of: ${choices.join(", ")}.`);
  }

  return value;
}

function getInteger(name, fallback, minimum, maximum) {
  const value = getInput(name, String(fallback));
  if (!/^\d+$/.test(value)) {
    throw new Error(`${name} must be an integer.`);
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}.`);
  }

  return parsed;
}

function getOptionalNonNegativeInteger(name) {
  const value = getInput(name, "");
  if (value.length === 0) {
    return "";
  }

  return getInteger(name, value, 0, Number.MAX_SAFE_INTEGER);
}

function getOptionalPositiveInteger(name) {
  const value = getInput(name, "");
  if (value.length === 0) {
    return "";
  }

  return getInteger(name, value, 1, Number.MAX_SAFE_INTEGER);
}

function parseList(value) {
  return value.split(",").map(item => item.trim()).filter(item => item.length !== 0);
}

function splitExtraArgs(value) {
  if (value.length === 0) {
    return [];
  }

  return value.split(/\r?\n/).map(item => item.trim()).filter(item => item.length !== 0);
}

function defaultReportDirectory() {
  return process.env.BUILD_ARTIFACTSTAGINGDIRECTORY
    ? path.join(process.env.BUILD_ARTIFACTSTAGINGDIRECTORY, "picket")
    : path.resolve("picket-results");
}

function defaultCachePath() {
  return process.env.PIPELINE_WORKSPACE
    ? path.join(process.env.PIPELINE_WORKSPACE, ".picket", "cache")
    : path.resolve(".picket", "cache");
}

function pathEquals(left, right) {
  if (!left || !right) {
    return false;
  }

  return path.resolve(left) === path.resolve(right);
}

function isDirectory(value) {
  try {
    return fs.statSync(value).isDirectory();
  }
  catch {
    return false;
  }
}

function toInputEnvironmentName(name) {
  return name.replace(/([a-z])([A-Z])/g, "$1_$2").replace(/[^A-Za-z0-9]/g, "_").toUpperCase();
}

function toSafeText(value) {
  return typeof value === "string" ? value : "";
}

function escapeProperty(value) {
  return escapeMessage(value).replace(/;/g, "%3B").replace(/]/g, "%5D");
}

function escapeMessage(value) {
  return String(value)
    .replace(/%/g, "%AZP25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
}

module.exports = {
  createPicketArguments,
  emitAnnotations,
  escapeMessage,
  escapeProperty,
  isScannerError,
  shouldFail,
  readInputs
};
