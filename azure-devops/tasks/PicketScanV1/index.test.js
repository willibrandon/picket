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
  assert.deepEqual(args.slice(args.indexOf("--azure-devops-feed"), args.indexOf("--azure-devops-feed") + 2), ["--azure-devops-feed", "release"]);
  assert.deepEqual(args.slice(args.indexOf("--azure-devops-package"), args.indexOf("--azure-devops-package") + 2), ["--azure-devops-package", "Picket.Sample"]);
  assert.deepEqual(args.slice(args.indexOf("--azure-devops-package-version"), args.indexOf("--azure-devops-package-version") + 2), ["--azure-devops-package-version", "1.2.3"]);
  assert.deepEqual(args.slice(args.indexOf("--azure-devops-max-package-megabytes"), args.indexOf("--azure-devops-max-package-megabytes") + 2), ["--azure-devops-max-package-megabytes", "50"]);
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
