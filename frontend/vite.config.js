import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const serverPort = Number(process.env.SPRAYCAN_SERVER_PORT || 8787);

export default defineConfig({
  plugins: [react()],
  server: {
    port: 4173,
    proxy: {
      "/api": `http://127.0.0.1:${serverPort}`,
    },
  },
});
