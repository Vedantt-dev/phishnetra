import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Served by the FastAPI backend at /dashboard/ in production; proxied to it in dev.
export default defineConfig({
  base: "/dashboard/",
  plugins: [react()],
  build: { chunkSizeWarningLimit: 800 },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", ws: true },
      "/health": "http://localhost:8000",
    },
  },
});
