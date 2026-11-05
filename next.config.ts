import type { NextConfig } from "next";
const config: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  devIndicators: false,
  async headers() {
    return [{source: "/(.*)", headers: [
      {key: "X-Content-Type-Options", value: "nosniff"},
      {key: "Referrer-Policy", value: "strict-origin-when-cross-origin"},
      {key: "X-Frame-Options", value: "DENY"},
      {key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()"},
      {key: "Content-Security-Policy", value: `default-src 'self'; script-src 'self' 'unsafe-inline'${process.env.NODE_ENV === "development" ? " 'unsafe-eval'" : ""}; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'`}
    ]}];
  }
};
export default config;
