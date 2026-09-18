/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The API base is read at request time so one build can point at a local
  // uvicorn, a staging API Gateway or production without rebuilding.
  env: {
    CLOUDWASTE_API_URL: process.env.CLOUDWASTE_API_URL ?? "http://127.0.0.1:8000",
  },
};
export default nextConfig;
