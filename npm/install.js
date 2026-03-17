const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const VERSION = require("./package.json").version;
const REPO = "estoppl/estoppl";

const PLATFORM_MAP = {
  "darwin-arm64": "estoppl-darwin-aarch64",
  "darwin-x64": "estoppl-darwin-x86_64",
  "linux-arm64": "estoppl-linux-aarch64",
  "linux-x64": "estoppl-linux-x86_64",
};

const key = `${process.platform}-${process.arch}`;
const artifact = PLATFORM_MAP[key];
if (!artifact) {
  console.error(
    `estoppl: unsupported platform ${key}. Supported: ${Object.keys(PLATFORM_MAP).join(", ")}`
  );
  process.exit(1);
}

const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${artifact}.tar.gz`;
const binDir = path.join(__dirname, "bin");
fs.mkdirSync(binDir, { recursive: true });

const binPath = path.join(binDir, "estoppl");

// Skip download if binary already exists (e.g. re-running postinstall)
if (fs.existsSync(binPath)) {
  process.exit(0);
}

console.log(`Downloading estoppl v${VERSION} for ${key}...`);

try {
  execSync(`curl -sL "${url}" | tar xz -C "${binDir}"`, { stdio: "inherit" });
  fs.renameSync(path.join(binDir, artifact), binPath);
  fs.chmodSync(binPath, 0o755);
  console.log("estoppl installed successfully.");
} catch (err) {
  console.error(`Failed to download estoppl: ${err.message}`);
  console.error(
    `You can download manually from https://github.com/${REPO}/releases`
  );
  process.exit(1);
}
