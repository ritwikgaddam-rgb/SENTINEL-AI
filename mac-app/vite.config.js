import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const appDirectory = fileURLToPath(new URL(".", import.meta.url));
const logoDirectory = fileURLToPath(new URL("../assets/logos/", import.meta.url));

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
    fs: { allow: [appDirectory, logoDirectory] },
  },
});
