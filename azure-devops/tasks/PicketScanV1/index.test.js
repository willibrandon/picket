"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const task = require("./index.js");

test("escapeProperty neutralizes Azure logging command delimiters", () => {
  assert.equal(
    task.escapeProperty("src/file.js];type=error;name=owned%\r\nnext"),
    "src/file.js%5D%3Btype=error%3Bname=owned%AZP25%0D%0Anext");
});

test("escapeMessage neutralizes Azure logging command message breaks", () => {
  assert.equal(
    task.escapeMessage("line 1%\r\nline 2"),
    "line 1%AZP25%0D%0Aline 2");
});

test("emitAnnotations escapes finding-controlled file paths and messages", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "picket-ado-task-"));
  const jsonlPath = path.join(root, "picket.jsonl");
  const finding = {
    file: "src/evil.js];type=error;sourcepath=owned\r\nnext",
    ruleId: "rule%0\nid",
    startLine: 7
  };
  fs.writeFileSync(jsonlPath, `${JSON.stringify(finding)}\n`, "utf8");

  try {
    const logs = captureConsoleLogs(() => {
      assert.equal(task.emitAnnotations(jsonlPath, 10), 1);
    });

    assert.deepEqual(logs, [
      "##vso[task.logissue type=warning;sourcepath=src/evil.js%5D%3Btype=error%3Bsourcepath=owned%0D%0Anext;linenumber=7;]Picket finding rule%AZP250%0Aid"
    ]);
  }
  finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("createPicketArguments forwards Azure Artifacts package selectors", () => {
  const inputs = {
    target: ".",
    profile: "picket",
    rulePacks: ["picket-strict", "picket-experimental"],
    redact: 100,
    cache: false,
    onlyVerified: false,
    verify: false,
    azureDevOpsOrganization: "willibrandon",
    azureDevOpsTokenKind: "pat",
    azureDevOpsIncludePackages: true,
    azureDevOpsFeed: "release",
    azureDevOpsPackage: "Picket.Sample",
    azureDevOpsPackageVersion: "1.2.3",
    azureDevOpsMaxPackageMegabytes: 50,
    extraArgs: []
  };

  const args = task.createPicketArguments(inputs, new Map());

  assert.ok(args.includes("--azure-devops-include-packages"));
  assert.deepEqual(
    args.filter((value, index) => value === "--rule-pack" || args[index - 1] === "--rule-pack"),
    ["--rule-pack", "picket-strict", "--rule-pack", "picket-experimental"]);
  assert.deepEqual(args.slice(args.indexOf("--azure-devops-feed"), args.indexOf("--azure-devops-feed") + 2), ["--azure-devops-feed", "release"]);
  assert.deepEqual(args.slice(args.indexOf("--azure-devops-package"), args.indexOf("--azure-devops-package") + 2), ["--azure-devops-package", "Picket.Sample"]);
  assert.deepEqual(args.slice(args.indexOf("--azure-devops-package-version"), args.indexOf("--azure-devops-package-version") + 2), ["--azure-devops-package-version", "1.2.3"]);
  assert.deepEqual(args.slice(args.indexOf("--azure-devops-max-package-megabytes"), args.indexOf("--azure-devops-max-package-megabytes") + 2), ["--azure-devops-max-package-megabytes", "50"]);
});

test("createPicketArguments forwards the native ignore path", () => {
  const inputs = {
    target: ".",
    profile: "picket",
    rulePacks: [],
    redact: 100,
    baselinePath: "",
    ignorePath: ".picketignore",
    cache: false,
    onlyVerified: false,
    verify: false,
    extraArgs: []
  };

  const args = task.createPicketArguments(inputs, new Map());

  assert.deepEqual(
    args.slice(args.indexOf("--ignore-path"), args.indexOf("--ignore-path") + 2),
    ["--ignore-path", ".picketignore"]);
});

test("createPicketArguments forwards a Docker archive as the sole primary source", () => {
  const inputs = makeScanInputs({
    target: "/agent/work/repository",
    dockerArchive: "/agent/temp/image.tar",
    maxArchiveDepth: 2,
    maxArchiveEntries: 100000,
    maxArchiveMegabytes: 4096,
    maxArchiveRatio: 1000
  });

  const args = task.createPicketArguments(inputs, new Map());

  assert.deepEqual(args.slice(0, 5), [
    "scan",
    "--docker-archive",
    "/agent/temp/image.tar",
    "--profile",
    "picket"
  ]);
  assert.equal(args.includes("/agent/work/repository"), false);
  assert.deepEqual(
    args.slice(args.indexOf("--max-archive-megabytes"), args.indexOf("--max-archive-megabytes") + 2),
    ["--max-archive-megabytes", "4096"]);
});

test("createPicketArguments forwards an OCI archive as the sole primary source", () => {
  const inputs = makeScanInputs({
    target: "/agent/work/repository",
    ociArchive: "/agent/temp/image-oci.tar"
  });

  const args = task.createPicketArguments(inputs, new Map());

  assert.deepEqual(args.slice(0, 5), [
    "scan",
    "--oci-archive",
    "/agent/temp/image-oci.tar",
    "--profile",
    "picket"
  ]);
  assert.equal(args.includes("/agent/work/repository"), false);
});

test("createPicketArguments forwards registry controls without treating the image as a path", () => {
  const inputs = makeScanInputs({
    target: "/agent/work/repository",
    registryImage: "registry.example/team/app:1.2.3",
    registryEndpoint: "https://mirror.example/v2",
    registryAuthEndpoint: "https://auth.example/token",
    registryUsernameEnv: "REGISTRY_USERNAME",
    registryPasswordEnv: "REGISTRY_PASSWORD",
    registryPlatform: "linux/arm64/v8",
    registryMaxImageMegabytes: 768,
    allowNonPublicSourceEndpoints: true,
    allowInsecureSourceEndpoints: true
  });

  const args = task.createPicketArguments(inputs, new Map());

  assert.deepEqual(args.slice(0, 5), [
    "scan",
    "--registry-image",
    "registry.example/team/app:1.2.3",
    "--profile",
    "picket"
  ]);
  assert.equal(args.includes("/agent/work/repository"), false);
  assert.deepEqual(
    args.slice(args.indexOf("--registry-endpoint"), args.indexOf("--registry-endpoint") + 2),
    ["--registry-endpoint", "https://mirror.example/v2"]);
  assert.deepEqual(
    args.slice(args.indexOf("--registry-auth-endpoint"), args.indexOf("--registry-auth-endpoint") + 2),
    ["--registry-auth-endpoint", "https://auth.example/token"]);
  assert.deepEqual(
    args.slice(args.indexOf("--registry-username-env"), args.indexOf("--registry-username-env") + 2),
    ["--registry-username-env", "REGISTRY_USERNAME"]);
  assert.deepEqual(
    args.slice(args.indexOf("--registry-password-env"), args.indexOf("--registry-password-env") + 2),
    ["--registry-password-env", "REGISTRY_PASSWORD"]);
  assert.deepEqual(
    args.slice(args.indexOf("--registry-platform"), args.indexOf("--registry-platform") + 2),
    ["--registry-platform", "linux/arm64/v8"]);
  assert.deepEqual(
    args.slice(args.indexOf("--registry-max-image-megabytes"), args.indexOf("--registry-max-image-megabytes") + 2),
    ["--registry-max-image-megabytes", "768"]);
  assert.equal(args.includes("--allow-non-public-source-endpoints"), true);
  assert.equal(args.includes("--allow-insecure-source-endpoints"), true);
});

test("createPicketArguments omits a positional target for Azure DevOps enumeration", () => {
  const inputs = makeScanInputs({
    target: "/agent/work/repository",
    azureDevOpsSourceSelected: true,
    azureDevOpsOrganization: "example",
    azureDevOpsProject: "project"
  });

  const args = task.createPicketArguments(inputs, new Map());

  assert.deepEqual(args.slice(0, 3), ["scan", "--profile", "picket"]);
  assert.equal(args.includes("/agent/work/repository"), false);
  assert.deepEqual(
    args.slice(args.indexOf("--azure-devops-organization"), args.indexOf("--azure-devops-organization") + 2),
    ["--azure-devops-organization", "example"]);
});

test("createPicketArguments bounds live verification requests", () => {
  const inputs = {
    target: ".",
    profile: "picket",
    rulePacks: [],
    redact: 100,
    cache: false,
    onlyVerified: false,
    verify: true,
    liveMaxRequests: 40,
    liveMaxRequestsPerProvider: 10,
    extraArgs: []
  };

  const args = task.createPicketArguments(inputs, new Map());

  assert.ok(args.includes("--verify"));
  assert.deepEqual(
    args.slice(args.indexOf("--live-max-requests"), args.indexOf("--live-max-requests") + 2),
    ["--live-max-requests", "40"]);
  assert.deepEqual(
    args.slice(args.indexOf("--live-max-requests-per-provider"), args.indexOf("--live-max-requests-per-provider") + 2),
    ["--live-max-requests-per-provider", "10"]);
});

test("readInputs rejects a zero live request budget", () => {
  withEnvironment({
    INPUT_liveMaxRequests: "0"
  }, () => {
    assert.throws(
      () => task.readInputs(),
      /liveMaxRequests must be between 1 and/);
  });
});

test("readInputs rejects package selectors when package scanning is disabled", () => {
  withEnvironment({
    INPUT_azureDevOpsIncludePackages: "false",
    INPUT_azureDevOpsFeed: "release"
  }, () => {
    assert.throws(
      () => task.readInputs(),
      /Azure Artifacts feed, package, and package limit settings require azureDevOpsIncludePackages\./);
  });
});

test("readInputs rejects a package limit when package scanning is disabled", () => {
  withEnvironment({
    INPUT_azureDevOpsIncludePackages: "false",
    INPUT_azureDevOpsMaxPackageMegabytes: "50"
  }, () => {
    assert.throws(
      () => task.readInputs(),
      /Azure Artifacts feed, package, and package limit settings require azureDevOpsIncludePackages\./);
  });
});

test("readInputs requires a package name for an exact package version", () => {
  withEnvironment({
    INPUT_azureDevOpsIncludePackages: "true",
    INPUT_azureDevOpsPackageVersion: "1.2.3"
  }, () => {
    assert.throws(
      () => task.readInputs(),
      /azureDevOpsPackageVersion requires azureDevOpsPackage\./);
  });
});

test("readInputs normalizes and deduplicates built-in rule packs", () => {
  withEnvironment({
    INPUT_rulePacks: "PICKET-STRICT,picket-experimental,picket-strict"
  }, () => {
    assert.deepEqual(task.readInputs().rulePacks, ["picket-strict", "picket-experimental"]);
  });
});

test("readInputs rejects unknown built-in rule packs", () => {
  withEnvironment({
    INPUT_rulePacks: "unknown"
  }, () => {
    assert.throws(
      () => task.readInputs(),
      /Unsupported built-in rule pack 'unknown'\. Use picket-strict or picket-experimental\./);
  });
});

test("readInputs preserves the build sources directory when no source is explicit", () => {
  withEnvironment({
    BUILD_SOURCESDIRECTORY: "/agent/work/repository",
    INPUT_target: ""
  }, () => {
    const inputs = task.readInputs();

    assert.equal(inputs.target, "/agent/work/repository");
    assert.equal(inputs.dockerArchive, "");
    assert.equal(inputs.ociArchive, "");
    assert.equal(inputs.registryImage, "");
    assert.equal(inputs.azureDevOpsSourceSelected, false);
  });
});

test("readInputs ignores the file control workspace fallback when a Docker archive is explicit", () => {
  const sourceDirectory = process.cwd();
  withEnvironment({
    BUILD_SOURCESDIRECTORY: sourceDirectory,
    INPUT_target: sourceDirectory,
    INPUT_dockerArchive: "/agent/temp/image.tar"
  }, () => {
    const inputs = task.readInputs();

    assert.equal(inputs.target, "");
    assert.equal(inputs.dockerArchive, "/agent/temp/image.tar");
    assert.equal(inputs.azureDevOpsSourceSelected, false);
  });
});

test("readInputs accepts registry bearer authentication and endpoint policy", () => {
  withEnvironment({
    INPUT_registryImage: "ghcr.io/example/app:latest",
    INPUT_registryTokenEnv: "REGISTRY_TOKEN",
    INPUT_registryMaxImageMegabytes: "512",
    INPUT_allowNonPublicSourceEndpoints: "true"
  }, () => {
    const inputs = task.readInputs();

    assert.equal(inputs.target, "");
    assert.equal(inputs.registryImage, "ghcr.io/example/app:latest");
    assert.equal(inputs.registryTokenEnv, "REGISTRY_TOKEN");
    assert.equal(inputs.registryMaxImageMegabytes, 512);
    assert.equal(inputs.allowNonPublicSourceEndpoints, true);
    assert.equal(inputs.allowInsecureSourceEndpoints, false);
  });
});

test("readInputs rejects conflicting primary sources", () => {
  withEnvironment({
    INPUT_target: "/agent/work/repository",
    INPUT_dockerArchive: "/agent/temp/image.tar"
  }, () => {
    assert.throws(
      () => task.readInputs(),
      /target, dockerArchive, ociArchive, registryImage, and Azure DevOps source inputs are mutually exclusive/);
  });
});

test("readInputs rejects a registry image combined with Azure DevOps enumeration", () => {
  withEnvironment({
    INPUT_registryImage: "example/app:latest",
    INPUT_azureDevOpsOrganization: "example"
  }, () => {
    assert.throws(
      () => task.readInputs(),
      /target, dockerArchive, ociArchive, registryImage, and Azure DevOps source inputs are mutually exclusive/);
  });
});

test("readInputs rejects registry controls without a registry image", () => {
  withEnvironment({
    INPUT_registryPlatform: "linux/amd64"
  }, () => {
    assert.throws(
      () => task.readInputs(),
      /Registry source options require registryImage\./);
  });
});

test("readInputs rejects endpoint policy without a remote source", () => {
  withEnvironment({
    INPUT_allowNonPublicSourceEndpoints: "true"
  }, () => {
    assert.throws(
      () => task.readInputs(),
      /Source endpoint policy inputs require registryImage or Azure DevOps source inputs\./);
  });
});

test("readInputs permits endpoint policy for Azure DevOps enumeration", () => {
  withEnvironment({
    INPUT_azureDevOpsOrganization: "example",
    INPUT_allowNonPublicSourceEndpoints: "true"
  }, () => {
    const inputs = task.readInputs();

    assert.equal(inputs.azureDevOpsSourceSelected, true);
    assert.equal(inputs.allowNonPublicSourceEndpoints, true);
  });
});

test("readInputs rejects mixed or incomplete registry authentication", () => {
  const invalidAuthentication = [
    {
      INPUT_registryTokenEnv: "REGISTRY_TOKEN",
      INPUT_registryUsernameEnv: "REGISTRY_USERNAME",
      INPUT_registryPasswordEnv: "REGISTRY_PASSWORD"
    },
    { INPUT_registryUsernameEnv: "REGISTRY_USERNAME" },
    { INPUT_registryPasswordEnv: "REGISTRY_PASSWORD" }
  ];

  for (const environment of invalidAuthentication) {
    withEnvironment({
      INPUT_registryImage: "example/app:latest",
      ...environment
    }, () => {
      assert.throws(
        () => task.readInputs(),
        /Registry authentication accepts either registryTokenEnv or both registryUsernameEnv and registryPasswordEnv\./);
    });
  }
});

test("readInputs rejects a non-positive registry image limit", () => {
  withEnvironment({
    INPUT_registryImage: "example/app:latest",
    INPUT_registryMaxImageMegabytes: "0"
  }, () => {
    assert.throws(
      () => task.readInputs(),
      /registryMaxImageMegabytes must be between 1 and/);
  });
});

test("scanner errors fail even when a partial report contains findings", () => {
  assert.equal(task.isScannerError(2, 7), true);
  assert.equal(task.shouldFail("never", 2, 7), false);
});

test("finding exits remain subject to the configured failure policy", () => {
  assert.equal(task.isScannerError(1, 7), false);
  assert.equal(task.shouldFail("findings", 1, 7), true);
  assert.equal(task.shouldFail("never", 1, 7), false);
});

test("nonzero exits without findings are scanner errors", () => {
  assert.equal(task.isScannerError(1, 0), true);
});

function captureConsoleLogs(callback) {
  const originalLog = console.log;
  const logs = [];
  console.log = value => logs.push(String(value));
  try {
    callback();
  }
  finally {
    console.log = originalLog;
  }

  return logs;
}

function withEnvironment(values, callback) {
  const previous = new Map();
  for (const [name, value] of Object.entries(values)) {
    previous.set(name, process.env[name]);
    process.env[name] = value;
  }

  try {
    callback();
  }
  finally {
    for (const [name, value] of previous) {
      if (value === undefined) {
        delete process.env[name];
      }
      else {
        process.env[name] = value;
      }
    }
  }
}

function makeScanInputs(overrides = {}) {
  return {
    target: ".",
    dockerArchive: "",
    ociArchive: "",
    registryImage: "",
    registryEndpoint: "",
    registryAuthEndpoint: "",
    registryTokenEnv: "",
    registryUsernameEnv: "",
    registryPasswordEnv: "",
    registryPlatform: "",
    registryMaxImageMegabytes: "",
    azureDevOpsSourceSelected: false,
    profile: "picket",
    rulePacks: [],
    redact: 100,
    cache: false,
    onlyVerified: false,
    verify: false,
    allowNonPublicSourceEndpoints: false,
    allowInsecureSourceEndpoints: false,
    extraArgs: [],
    ...overrides
  };
}
