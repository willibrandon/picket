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
