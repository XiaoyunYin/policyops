// Keep package metadata and license/notice texts for the exact web dependency tree.
import { readdirSync, mkdirSync, copyFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const source = "/opt/policyops/apps/web/node_modules";
const output = "/opt/web-notices";
mkdirSync(output, { recursive: true });
const inventory = [];
function walk(directory) {
  for (const item of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, item.name);
    if (item.isSymbolicLink()) continue;
    if (item.isDirectory()) walk(path);
    else if (/^(licen[cs]e|notice|copying)([._-]|$)/i.test(item.name) || item.name === "package.json") {
      const name = relative(source, path);
      const target = join(output, name);
      mkdirSync(join(target, ".."), { recursive: true });
      copyFileSync(path, target);
      inventory.push(name);
    }
  }
}
walk(source);
writeFileSync(join(output, "inventory.json"), JSON.stringify(inventory.sort(), null, 2) + "\n");
