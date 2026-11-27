// content-pack.json must validate against the family's content-pack schema, so the Learning Hub can ingest the lab.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

describe("content pack", () => {
  it("content-pack.json validates against docs/content-pack.schema.json", () => {
    const schema = JSON.parse(readFileSync(path.join(root, "docs/content-pack.schema.json"), "utf8"));
    const pack = JSON.parse(readFileSync(path.join(root, "content-pack.json"), "utf8"));
    const ajv = new Ajv2020({ allErrors: true });
addFormats(ajv);
    const ok = ajv.validate(schema, pack);
    assert.equal(ok, true, ajv.errorsText(ajv.errors ?? []));
    assert.equal(pack.demo.id, "trusted-issuers");
  });
});
