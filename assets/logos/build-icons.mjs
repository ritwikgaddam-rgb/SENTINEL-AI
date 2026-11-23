import { execFileSync } from "node:child_process";
import {
  copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const logos = fileURLToPath(new URL(".", import.meta.url));
const repository = fileURLToPath(new URL("../../", import.meta.url));
const tauri = join(repository, "mac-app/node_modules/@tauri-apps/cli/tauri.js");
const macIcons = join(repository, "mac-app/src-tauri/icons");
const extension = join(repository, "chrome-extension");
const scratch = mkdtempSync(join(tmpdir(), "sentinelai-icons-"));

const themes = {
  navy: {
    background: "#03094B",
    icon: "SentinelAILogoIcon(Purple).svg",
    wordmark: "SentinelAILogoFull.svg",
  },
  orange: {
    background: "#541504",
    icon: "SentinelAILogoIcon(Orange).svg",
    wordmark: "SentinelAILogoTotal-NoBG(Orange).svg",
  },
};

function renderIcon(name, theme, inset, artworkInset, sizes = []) {
  const artwork = readFileSync(join(logos, theme.icon)).toString("base64");
  const source = join(scratch, name + ".svg");
  const output = join(scratch, name);
  // Put the official SVG on a theme tile without stretching or clipping it.
  const tileSize = 1024 - 2 * inset;
  const markSize = 1024 - 2 * artworkInset;
  writeFileSync(source, `<svg xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink"
       width="1024" height="1024" viewBox="0 0 1024 1024">
    <rect x="${inset}" y="${inset}" width="${tileSize}" height="${tileSize}"
          rx="180" fill="${theme.background}"/>
    <image x="${artworkInset}" y="${artworkInset}" width="${markSize}"
           height="${markSize}" preserveAspectRatio="xMidYMid meet"
           xlink:href="data:image/svg+xml;base64,${artwork}"/>
  </svg>`);
  const args = sizes.flatMap((size) => ["--png", String(size)]);
  execFileSync(process.execPath, [tauri, "icon", source, "--output", output, ...args], {
    stdio: "inherit",
  });
  return output;
}

try {
  mkdirSync(macIcons, { recursive: true });
  const mac = renderIcon("mac", themes.navy, 96, 146);
  for (const file of ["32x32.png", "128x128.png", "128x128@2x.png", "icon.png", "icon.icns"]) {
    copyFileSync(join(mac, file), join(macIcons, file));
  }

  const logoOutput = join(extension, "logos");
  mkdirSync(logoOutput, { recursive: true });
  const sizes = [16, 24, 32, 48, 128];
  for (const [name, theme] of Object.entries(themes)) {
    const output = join(extension, "icons", name);
    mkdirSync(output, { recursive: true });
    const raster = renderIcon("chrome-" + name, theme, 16, 48, sizes);
    for (const size of sizes) {
      copyFileSync(join(raster, `${size}x${size}.png`), join(output, `${size}.png`));
    }
    copyFileSync(join(logos, theme.wordmark), join(logoOutput, `${name}.svg`));
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
