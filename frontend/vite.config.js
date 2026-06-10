import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/cves": { target: "http://localhost:8000", changeOrigin: true },
      "/stats": { target: "http://localhost:8000", changeOrigin: true },
      "/refresh": { target: "http://localhost:8000", changeOrigin: true },
      "/health": { target: "http://localhost:8000", changeOrigin: true },
      "/cache": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
});