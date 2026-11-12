function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function encodeJson(value) {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)));
}

export async function onRequest({ request, env }) {
  if (request.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  // 只接受来自这个 Pages 网站本身的浏览器请求。
  // 这是基本限制，不等同于用户登录或完整的防滥用措施。
  const origin = request.headers.get("Origin");
  if (!origin || origin !== new URL(request.url).origin) {
    return jsonResponse({ error: "Forbidden" }, 403);
  }

  if (!env.COZE_APP_ID || !env.COZE_KID || !env.COZE_PRIVATE_KEY) {
    return jsonResponse({ error: "Cloudflare OAuth settings are missing" }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body" }, 400);
  }

  const sessionName = body?.session_name;
  if (
    typeof sessionName !== "string" ||
    !/^[0-9a-fA-F-]{36}$/.test(sessionName)
  ) {
    return jsonResponse({ error: "Invalid session_name" }, 400);
  }

  try {
    // 扣子生成的 private_key.pem 通常应以 BEGIN PRIVATE KEY 开头。
    const pem = env.COZE_PRIVATE_KEY.replace(/\\n/g, "\n");
    const match = pem.match(
      /-----BEGIN PRIVATE KEY-----([\s\S]+?)-----END PRIVATE KEY-----/
    );

    if (!match) {
      return jsonResponse(
        { error: "Private key format is invalid" },
        500
      );
    }

    const der = Uint8Array.from(
      atob(match[1].replace(/\s/g, "")),
      (char) => char.charCodeAt(0)
    );

    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      der,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      },
      false,
      ["sign"]
    );

    const now = Math.floor(Date.now() / 1000);
    const jwtHeader = {
      alg: "RS256",
      typ: "JWT",
      kid: env.COZE_KID,
    };
    const jwtPayload = {
      iss: env.COZE_APP_ID,
      aud: "api.coze.cn",
      iat: now,
      exp: now + 300,
      jti: crypto.randomUUID(),
      session_name: sessionName,
    };

    const signingInput =
      `${encodeJson(jwtHeader)}.${encodeJson(jwtPayload)}`;

    const signature = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      privateKey,
      new TextEncoder().encode(signingInput)
    );

    const assertion =
      `${signingInput}.${base64Url(new Uint8Array(signature))}`;

    const tokenResponse = await fetch(
      "https://api.coze.cn/api/permission/oauth2/token",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${assertion}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
          duration_seconds: 900,
        }),
      }
    );

    const tokenData = await tokenResponse.json().catch(() => null);

    if (!tokenResponse.ok || !tokenData?.access_token) {
      console.error("Coze token request failed:", tokenResponse.status);
      return jsonResponse(
        { error: "Could not obtain a Coze access token" },
        502
      );
    }

    return jsonResponse({ access_token: tokenData.access_token });
  } catch (error) {
    console.error(
      "Token function failed:",
      error instanceof Error ? error.name : "UnknownError"
    );
    return jsonResponse({ error: "Token generation failed" }, 500);
  }
}
