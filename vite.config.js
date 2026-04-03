import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // During local dev, proxy /api calls to a local Express server (optional)
      // Remove this block if you're only deploying to Vercel
    },
  },
});
