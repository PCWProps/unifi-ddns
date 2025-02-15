// src/index.js

// Define properties for class names
var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __defProp2 = Object.defineProperty;
var __name2 = /* @__PURE__ */ __name((target, value) => __defProp2(target, "name", { value, configurable: true }), "__name");

// Custom exception classes for specific error handling
class BadRequestException extends Error {
  constructor(reason) {
    super(reason);
    this.status = 400;
    this.statusText = "Bad Request";
  }
}
__name2(BadRequestException, "BadRequestException");

class CloudflareApiException extends Error {
  constructor(reason) {
    super(reason);
    this.status = 500;
    this.statusText = "Internal Server Error";
  }
}
__name2(CloudflareApiException, "CloudflareApiException");

// Utility function to handle fetch requests with token authentication
async function _fetchWithToken(url, token, options = {}) {
  options.headers = {
    ...options.headers,
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`
  };
  try {
    const response = await fetch(url, options);
    if (!response.ok) {
      const error = await response.json();
      throw new CloudflareApiException(error.errors?.[0]?.message || "API request failed");
    }
    return response;
  } catch (err) {
    throw new CloudflareApiException(`Network error: ${err.message}`);
  }
}

// Cloudflare API class for managing DNS records
class Cloudflare {
  constructor({ token }) {
    this.cloudflare_url = process.env.CLOUDFLARE_URL || "https://api.cloudflare.com/client/v4";
    this.token = token;
  }

  async findZone(name) {
    const response = await _fetchWithToken(`${this.cloudflare_url}/zones?name=${name}`, this.token);
    const body = await response.json();
    if (!body.success || body.result.length === 0) {
      throw new CloudflareApiException(`Failed to find zone '${name}'`);
    }
    return body.result[0];
  }

  async findRecord(zone, name, isIPV4 = true) {
    const rrType = isIPV4 ? "A" : "AAAA";
    const response = await _fetchWithToken(`${this.cloudflare_url}/zones/${zone.id}/dns_records?name=${name}`, this.token);
    const body = await response.json();
    if (!body.success || body.result.length === 0) {
      throw new CloudflareApiException(`Failed to find DNS record '${name}'`);
    }
    return body.result?.filter((rr) => rr.type === rrType)?.[0] || null;
  }

  async updateRecord(record, value) {
    if (!record) {
      throw new CloudflareApiException("Record is undefined, cannot update.");
    }
    console.log("Updating record:", record, "with value:", value);
    record.content = value;
    const response = await _fetchWithToken(
      `${this.cloudflare_url}/zones/${record.zone_id}/dns_records/${record.id}`,
      this.token,
      {
        method: "PUT",
        body: JSON.stringify(record)
      }
    );
    const body = await response.json();
    if (!body.success) {
      throw new CloudflareApiException("Failed to update DNS record");
    }
    return body.result[0];
  }
}
__name2(Cloudflare, "Cloudflare");

function requireHttps(request) {
  if (process.env.NODE_ENV === "production") {
    const allowedHostnames = ["*.pcwprops.com", "*.dynamicmarching.com"]; // Add your allowed domains here
    const { protocol, hostname } = new URL(request.url);
    const forwardedProtocol = request.headers.get("x-forwarded-proto");

    // Function to check if the hostname matches any of the allowed patterns
    const isAllowedHostname = (hostname) => {
      return allowedHostnames.some(pattern => {
        const regex = new RegExp(`^${pattern.replace(/\*/g, '.*')}$`);
        return regex.test(hostname);
      });
    };

    if (protocol !== "https:" || forwardedProtocol !== "https") {
      if (!isAllowedHostname(hostname)) {
        throw new BadRequestException("Invalid redirection URL.");
      }
      const redirectUrl = new URL(request.url);
      redirectUrl.protocol = "https:";
      return Response.redirect(redirectUrl.toString(), 301);
    }
  }
  return null; // Skip redirection in development
}

// Function to parse Basic Authentication headers
function parseBasicAuth(request) {
  const authorization = request.headers.get("Authorization");
  if (!authorization) return {};
  const [, data] = authorization?.split(" ");
  const decoded = atob(data);
  const index = decoded.indexOf(":");
  if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
    throw new BadRequestException("Invalid authorization value.");
  }
  return {
    username: decoded?.substring(0, index),
    password: decoded?.substring(index + 1)
  };
}

// Main request handler
async function handleRequest(request) {
  // Temporarily disable HTTPS enforcement
  // const httpsRedirect = requireHttps(request);
  // if (httpsRedirect) return httpsRedirect;

  const { pathname } = new URL(request.url);

  if (pathname === "/") {
    return new Response("Worker is running locally!", { status: 200 });
  }

  if (pathname === "/favicon.ico" || pathname === "/robots.txt") {
    return new Response(null, { status: 204 });
  }

  if (!pathname.endsWith("/update")) {
    return new Response("Not Found.", { status: 404 });
  }

  const { username, password } = parseBasicAuth(request);
  const url = new URL(request.url);
  const params = url.searchParams;
  const token = params?.get("token") || password || "";
  if (!token) {
    throw new BadRequestException("Authorization token missing.");
  }
  const hostnameParam = params?.get("hostname") || params?.get("host") || params?.get("domains");
  const hostnames = hostnameParam?.split(",");
  const ipsParam = params.get("ips") || params.get("ip") || params.get("myip") || request.headers?.get("Cf-Connecting-Ip");
  const ips = ipsParam?.split(",");
  if (!hostnames || !ips || hostnames.length === 0 || ips.length === 0) {
    throw new BadRequestException("You must specify both hostname(s) and IP address(es)");
  }
  await Promise.all(
    ips.map(
      (ip) => informAPI(hostnames, ip.trim(), username, token)
    )
  );
  return new Response("good", {
    status: 200,
    headers: {
      "Content-Type": "text/plain;charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

// Function to inform the Cloudflare API
async function informAPI(hostnames, ip, name, token) {
  const cloudflare = new Cloudflare({ token });
  const isIPV4 = ip.includes(".");
  const zones = /* @__PURE__ */ new Map();
  await Promise.all(
    hostnames.map(async (hostname) => {
      const domainName = name && hostname.endsWith(name) ? name : hostname.replace(/.*?([^.]+\.[^.]+)$/, "$1");
      if (!zones.has(domainName)) {
        zones.set(domainName, await cloudflare.findZone(domainName));
      }
      const zone = zones.get(domainName);
      const record = await cloudflare.findRecord(zone, hostname, isIPV4);
      if (!record) {
        throw new CloudflareApiException(`Record not found for hostname '${hostname}'`);
      }
      await cloudflare.updateRecord(record, ip);
    })
  );
}

// Export default fetch handler
export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request);
    } catch (err) {
      console.error(`[Error]: ${err.constructor.name} - ${err.message}`);
      return new Response(err.message || "Unknown Error", {
        status: err.status || 500,
        headers: {
          "Content-Type": "text/plain;charset=UTF-8",
          "Cache-Control": "no-store"
        }
      });
    }
  }
};
