// The vendored files are byte for byte from their shared sources (re-vendor, do not edit).
// Pins live next to this test; if one fails, someone edited a vendored file by hand.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, test } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");

const PINS = {
  "src/components/JsonPane.jsx": "23b77832335718e30b6f62322f520ac6ada3d84be703316fa805b72bede4b48b",
  "src/components/JsonPane.css": "1e794d9470cf3b42d82b99927fcdcc41e5f61024afac92c926cae7afb66a8fbc",
  "src/top-menu/TopMenu.jsx": "80c2796c5b62ee3989cf218077b455e21a7e88d04dc66fd49d034249ef34a9da",
  "src/top-menu/top-menu.css": "ebddfcadc0e17bfebc981317a2720ddfe319818e7af1e268dae77826c5940651",
};

describe("vendored pins", () => {
  for (const [file, pin] of Object.entries(PINS)) {
    test(`${file} matches its shared source`, () => {
      const got = createHash("sha256").update(readFileSync(path.join(root, file))).digest("hex");
      expect(got).toBe(pin);
    });
  }
});
