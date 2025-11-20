// ====================================================================================
// Cloudflare Worker: Real-Time Dashboard (完整、未省略版本)
// ====================================================================================

// --- 配置 ---
const API_SOURCES = [
  { name: "bitz", url: "https://s3.bbdmfetch.com/api/v1/client/subscribe?token=7982fbf81d9afb7e130c7ee79d9ece84" },
  { name: "bitz2", url: "https://f2.bbdmfetch.com/api/v1/client/subscribe?token=01dc3853cee997f7a04c942276c24dc5" },
  { name: "Flow", url: "https://api.xmancdn.com/osubscribe.php?token2=ynx372dy-ecbe9a840cuokrcbp0tpez&sip002=1" },
  { name: "WD", url: "https://wd-purple.com/subscribe/bxzekg-hvfbx9fs-TWu5Nm4ZHeCl" },
  { name: "YT", url: "https://43de9944743a.oxycontinon.com/osubscribe.php?sid=117446&token=6DS1UX5b8xzW&sip002=1" },
  //{ name: "Apt", url: "https://s00.btfpi.cn/ss?token=543546fdee767a6920702c672886bc15" },

];

const CONFIG = {
  // [新功能] true: 啟用人機驗證, false: 禁用人機驗證 (方便調試)
  ENABLE_TURNSTILE: true,
  ACCESS_PASSWORD: "wuYang123@.@",
  // [請替換] 將這裡的金鑰替換為您自己的 Turnstile 金鑰
  // 站點金鑰，用於前端 getLoginHTML()
  TURNSTILE_SITE_KEY: "0x4AAAAAABkARpE_dFPIANlb",
  // 密鑰，用於後端 validateTurnstileToken()
  TURNSTILE_SECRET_KEY: "0x4AAAAAABkARtfcTzpVC0T5KYFSeyfLT4Y",
  // JWT 密鑰，請務必修改為您自己的隨機長字符串！
  JWT_SECRET: "change-this-to-a-very-secret-and-random-string-!@#$%^",
  AUTH_COOKIE_NAME: "dashboard_auth",
  V2BOARD_API_TOKEN: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwic2Vzc2lvbiI6IjE3NDA0MWZlYjkzMDg3ODRiZDcwYzI0ODU1ZGZkNDMxIn0.4YUw31rcfPpLrCa3VEpNYeWu148IiJyVY_el5RhWUok",
  RATE_LIMIT_PER_MINUTE: 60,
  MAX_RETRIES: 3,
  MAX_LOGS: 100,
  DEFAULT_ORDERS_PER_PAGE: 10,
  BALANCE_API_URL: "https://pay.91hk.cn/api.php?act=query&pid=1026&key=3Bub1DtLNBDTzJzZSwTL0nLRb0zU0nLL",
  ORDERS_API_URL: "https://pay.91hk.cn/api.php?act=orders&pid=1026&key=3Bub1DtLNBDTzJzZSwTL0nLRb0zU0nLL",
  SINGLE_ORDER_API_URL: "https://pay.91hk.cn/api.php?act=order&pid=1026&key=3Bub1DtLNBDTzJzZSwTL0nLRb0zU0nLL",
  V2BOARD_OVERRIDE_API_URL: "https://api.moon365.net/api/v1/yangyuaa/stat/getOverride",
  V2BOARD_SERVER_TODAY_RANK_API_URL: "https://api.moon365.net/api/v1/yangyuaa/stat/getServerTodayRank",
  V2BOARD_SERVER_LAST_RANK_API_URL: "https://api.moon365.net/api/v1/yangyuaa/stat/getServerLastRank",
  V2BOARD_USER_TODAY_RANK_API_URL: "https://api.moon365.net/api/v1/yangyuaa/stat/getUserTodayRank",
  V2BOARD_USER_LAST_RANK_API_URL: "https://api.moon365.net/api/v1/yangyuaa/stat/getUserLastRank",
  V2BOARD_ORDERS_API_URL: "https://api.moon365.net/api/v1/yangyuaa/order/fetch",
  V2BOARD_ORDER_DETAIL_API_URL: "https://api.moon365.net/api/v1/yangyuaa/order/detail",
  V2BOARD_USER_INFO_API_URL: "https://api.moon365.net/api/v1/yangyuaa/user/getUserInfoById",
};

// ====================================================================================
// 工具函式
// ====================================================================================

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const bufferToBase64Url = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const base64UrlToBuffer = (str) => new Uint8Array(atob(str.replace(/-/g, '+').replace(/_/g, '/')).split('').map(c => c.charCodeAt(0))).buffer;

const importKey = () => crypto.subtle.importKey("raw", textEncoder.encode(CONFIG.JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

async function createJwt() {
  const key = await importKey();
  const header = { alg: "HS256", typ: "JWT" };
  const payload = { exp: Math.floor(Date.now() / 1000) + (60 * 60), iat: Math.floor(Date.now() / 1000) };
  const headerB64 = bufferToBase64Url(textEncoder.encode(JSON.stringify(header)));
  const payloadB64 = bufferToBase64Url(textEncoder.encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign("HMAC", key, textEncoder.encode(`${headerB64}.${payloadB64}`));
  const signatureB64 = bufferToBase64Url(signature);
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

async function verifyJwt(token) {
  if (!token) return false;
  try {
    const key = await importKey();
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    if (!headerB64 || !payloadB64 || !signatureB64) return false;
    const isValid = await crypto.subtle.verify("HMAC", key, base64UrlToBuffer(signatureB64), textEncoder.encode(`${headerB64}.${payloadB64}`));
    if (!isValid) return false;
    const payload = JSON.parse(textDecoder.decode(base64UrlToBuffer(payloadB64)));
    if (payload.exp * 1000 < Date.now()) { return false; }
    return true;
  } catch (e) { return false; }
}

const getCookie = (request, name) => {
  const cookieStr = request.headers.get("Cookie") || "";
  const cookies = new Map(cookieStr.split(';').map(c => c.trim().split('=').map(decodeURIComponent)));
  return cookies.get(name);
};

const rateLimitTracker = new Map();

// 存储每个API源的初始流量和上次流量，用于计算运行期间流量差异
const initialTrafficData = new Map();
const initialNodeTrafficData = new Map(); // For V2Board node traffic
const initialUserTrafficData = new Map(); // For V2Board user traffic

const checkRateLimit = (apiName) => {
  const now = Date.now();
  const minute = Math.floor(now / 60000);
  const key = `${apiName}:${minute}`;
  const tracker = rateLimitTracker.get(key) || { count: 0 };
  if (tracker.count >= CONFIG.RATE_LIMIT_PER_MINUTE) return false;
  rateLimitTracker.set(key, { ...tracker, count: tracker.count + 1 });
  return true;
};

const parseSubscriptionHeader = (header) => {
  if (!header) return null;
  const result = {};
  header.split(";").forEach(pair => {
    const [key, value] = pair.trim().split("=");
    if (key && value) result[key.trim()] = value.trim();
  });
  return result;
};

const formatTimestamp = (timestamp) => {
  if (!timestamp || isNaN(timestamp)) return "N/A";
  return new Date(parseInt(timestamp) * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" });
};

const formatElapsedTime = (startTimestamp) => {
  if (!startTimestamp) return "N/A";
  const elapsed = Date.now() - startTimestamp;
  const days = Math.floor(elapsed / 86400000);
  const hours = Math.floor((elapsed % 86400000) / 3600000);
  const minutes = Math.floor((elapsed % 3600000) / 60000);
  return `${days}天 ${hours}時 ${minutes}分`;
};

async function validateTurnstileToken(token) {
  if (!token) return false;
  const formData = new FormData();
  formData.append("secret", CONFIG.TURNSTILE_SECRET_KEY);
  formData.append("response", token);
  try {
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: formData,
    });
    const result = await response.json();
    return result.success;
  } catch (e) {
    console.error("Turnstile validation error:", e);
    return false;
  }
}

// ====================================================================================
// 主路由和請求處理
// ====================================================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.headers.get("Upgrade") === "websocket") {
      const isAuthenticated = await verifyJwt(getCookie(request, CONFIG.AUTH_COOKIE_NAME));
      if (!isAuthenticated) return new Response("Forbidden", { status: 403 });
      const { 0: clientWs, 1: serverWs } = new WebSocketPair();
      serverWs.accept();
      handleWebSocketSession(serverWs, request);
      return new Response(null, { status: 101, webSocket: clientWs });
    }

    if (url.pathname === "/api/auth" && request.method === "POST") {
      return handleAuthApi(request);
    }

    // Add logout API endpoint
    if (url.pathname === "/api/logout" && request.method === "POST") {
      return handleLogoutApi(request);
    }

    if (url.pathname === "/dashboard") {
      const isAuthenticated = await verifyJwt(getCookie(request, CONFIG.AUTH_COOKIE_NAME));
      if (!isAuthenticated) {
        return Response.redirect(url.origin, 302);
      }
      return new Response(getDashboardHTML(), { headers: { "Content-Type": "text/html;charset=UTF-8" } });
    }

    if (url.pathname === "/") {
      const isAuthenticated = await verifyJwt(getCookie(request, CONFIG.AUTH_COOKIE_NAME));
      return new Response(getLoginHTML(isAuthenticated), { headers: { "Content-Type": "text/html;charset=UTF-8" } });
    }

    return new Response("Not Found", { status: 404 });
  },
};

// ====================================================================================
// API 處理器
// ====================================================================================

async function handleAuthApi(request) {
  try {
    const { password, turnstileToken } = await request.json();
    
    let isTurnstileValid = false;
    if (CONFIG.ENABLE_TURNSTILE) {
      isTurnstileValid = await validateTurnstileToken(turnstileToken);
      if (!isTurnstileValid) {
        return new Response(JSON.stringify({ success: false, message: "人機驗證失敗。" }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      }
    } else {
      isTurnstileValid = true;
    }

    if (password === CONFIG.ACCESS_PASSWORD) {
      const token = await createJwt();
      const headers = new Headers({ 'Content-Type': 'application/json' });
      headers.set('Set-Cookie', `${CONFIG.AUTH_COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600`);
      return new Response(JSON.stringify({ success: true }), { headers });
    } else {
      return new Response(JSON.stringify({ success: false, message: "密碼錯誤。" }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
  } catch (e) {
    return new Response(JSON.stringify({ success: false, message: "無效的請求。" }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
}

async function handleLogoutApi(request) {
  try {
    const headers = new Headers({ 'Content-Type': 'application/json' });
    // Expire the authentication cookie
    headers.set('Set-Cookie', `${CONFIG.AUTH_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
    return new Response(JSON.stringify({ success: true, message: "已登出。" }), { headers });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, message: "登出失敗。" }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}

// ====================================================================================
// WebSocket 核心邏輯
// ====================================================================================

async function handleWebSocketSession(ws, request) {
  const sendMessage = (type, payload) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type, payload }));
    }
  };

  const logMessage = (message, type = "info") => sendMessage("log", { message, type });
  const notify = (message, type = "info") => sendMessage("notification", { message, type });

  const fetchTrafficData = async (source, attempt = 1) => {
    if (!checkRateLimit(source.name)) {
      const errorMsg = `[${source.name}] 已達速率限制: 每分鐘最多 ${CONFIG.RATE_LIMIT_PER_MINUTE} 次。`;
      logMessage(errorMsg, "warn");
      return { sourceName: source.name, error: "已達速率限制", type: "rate_limit", details: errorMsg };
    }

    try {
      const response = await fetch(source.url, { headers: { "User-Agent": "Clash / shadowrocket" } });
      if (!response.ok) throw new Error(`API 請求失敗，狀態碼: ${response.status}`);

      const userInfo = parseSubscriptionHeader(response.headers.get("subscription-userinfo"));
      if (!userInfo || !userInfo.total) throw new Error("返回的訂閱數據無效");

      const upload = parseInt(userInfo.upload) || 0;
      const download = parseInt(userInfo.download) || 0;
      const total = parseInt(userInfo.total) || 0;

      // Calculate traffic used during runtime
      let runtimeUpload = 0;
      let runtimeDownload = 0;
      if (initialTrafficData.has(source.name)) {
        const initial = initialTrafficData.get(source.name);
        runtimeUpload = upload - initial.upload;
        runtimeDownload = download - initial.download;
      } else {
        // First fetch, set initial data
        initialTrafficData.set(source.name, { time: Date.now(), upload, download });
      }

      const usagePercent = total > 0 ? ((upload + download) / total) * 100 : 0;

      if (usagePercent >= 90) { // Warning at 90% usage
        notify(`[${source.name}] 流量已使用 ${usagePercent.toFixed(1)}%。`, "warn");
      } else if (usagePercent >= 75) { // Info at 75% usage
        notify(`[${source.name}] 流量已使用 ${usagePercent.toFixed(1)}%。`, "info");
      }

      return {
        sourceName: source.name,
        upload, download, total,
        remaining: total - (upload + download),
        usagePercent: usagePercent.toFixed(2),
        expiry: formatTimestamp(userInfo.expire),
        elapsedTime: formatElapsedTime(initialTrafficData.get(source.name)?.time),
        runtimeUpload,
        runtimeDownload,
        runtimeTotal: runtimeUpload + runtimeDownload,
      };
    } catch (e) {
      if (attempt < CONFIG.MAX_RETRIES) {
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
        logMessage(`[${source.name}] 獲取流量數據失敗，正在重試 (嘗試 ${attempt}/${CONFIG.MAX_RETRIES}): ${e.message}`, "warn");
        return fetchTrafficData(source, attempt + 1);
      }
      logMessage(`[${source.name}] 獲取流量數據最終失敗: ${e.message}`, "error");
      return { sourceName: source.name, error: "處理錯誤", type: "network_error", details: e.message };
    }
  };

  const fetchApiData = async (url, type, attempt = 1, headers = {}, method = 'GET', body = null) => {
    try {
      const options = { method, headers };
      if (body) {
        options.body = JSON.stringify(body);
        options.headers['Content-Type'] = 'application/json';
      }
      
      const response = await fetch(url, options);
      if (!response.ok) throw new Error(`請求失敗，狀態碼: ${response.status}`);
      const data = await response.json();

      // For single order, the API returns { code: 1, msg: "succ", trade_no: "...", ... }
      // For orders list and balance, it returns { code: 1, msg: "succ", data: [...], ... }
      if (data.code !== undefined && data.code !== 1) { // Check for 'code' for 91hk API
        // Special handling for single order "not found" which might still return code 1 but empty data array
        // or an error message directly.
        if (type === "單個訂單" && data.msg && data.msg.includes("不存在")) {
          return { error: `未找到 ${type}`, details: '沒有找到符合該訂單號的記錄。' };
        }
        throw new Error(data.msg || '未知的 API 錯誤');
      }

      return data;
    } catch (e) {
      logMessage(`獲取 ${type} 失敗: ${e.message}`, "error");
      if (attempt < CONFIG.MAX_RETRIES) {
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
        logMessage(`獲取 ${type} 失敗，正在重試 (嘗試 ${attempt}/${CONFIG.MAX_RETRIES}): ${e.message}`, "warn");
        return fetchApiData(url, type, attempt + 1, headers, method, body);
      }
      return { error: `獲取 ${type} 失敗`, details: e.message };
    }
  };

  const fetchV2BoardOverrideData = async () => {
    const headers = { 'Authorization': `${CONFIG.V2BOARD_API_TOKEN}` }; // Removed "Bearer"
    return fetchApiData(CONFIG.V2BOARD_OVERRIDE_API_URL, "V2Board 概覽", 1, headers);
  };

  const fetchV2BoardServerRankData = async (isToday) => {
    const headers = { 'Authorization': `${CONFIG.V2BOARD_API_TOKEN}` }; // Removed "Bearer"
    const url = isToday ? CONFIG.V2BOARD_SERVER_TODAY_RANK_API_URL : CONFIG.V2BOARD_SERVER_LAST_RANK_API_URL;
    const type = isToday ? "今日節點排行" : "昨日節點排行";
    const data = await fetchApiData(url, type, 1, headers);
    
    if (data && data.data) {
      return data.data.map(server => {
        const id = server.server_id;
        let runtimeUpload = 0;
        let runtimeDownload = 0;
        const key = `${isToday ? 'today' : 'last'}_${id}`;
        
        if (initialNodeTrafficData.has(key)) {
          const initial = initialNodeTrafficData.get(key);
          runtimeUpload = server.u - initial.u;
          runtimeDownload = server.d - initial.d;
        } else {
          initialNodeTrafficData.set(key, { time: Date.now(), u: server.u, d: server.d });
        }
        
        return {
          ...server,
          runtimeUpload,
          runtimeDownload,
          runtimeTotal: runtimeUpload + runtimeDownload,
          elapsedTime: formatElapsedTime(initialNodeTrafficData.get(key)?.time),
        };
      });
    }
    return [];
  };

  const fetchV2BoardUserRankData = async (isToday) => {
    const headers = { 'Authorization': `${CONFIG.V2BOARD_API_TOKEN}` }; // Removed "Bearer"
    const url = isToday ? CONFIG.V2BOARD_USER_TODAY_RANK_API_URL : CONFIG.V2BOARD_USER_LAST_RANK_API_URL;
    const type = isToday ? "今日用戶排行" : "昨日用戶排行";
    const data = await fetchApiData(url, type, 1, headers);
    
    if (data && data.data) {
      return data.data.map(user => {
        const id = user.user_id;
        let runtimeUpload = 0;
        let runtimeDownload = 0;
        const key = `${isToday ? 'today' : 'last'}_user_${id}`;
        
        if (initialUserTrafficData.has(key)) {
          const initial = initialUserTrafficData.get(key);
          runtimeUpload = user.u - initial.u;
          runtimeDownload = user.d - initial.d;
        } else {
          initialUserTrafficData.set(key, { time: Date.now(), u: user.u, d: user.d });
        }
        
        return {
          ...user,
          runtimeUpload,
          runtimeDownload,
          runtimeTotal: runtimeUpload + runtimeDownload,
          elapsedTime: formatElapsedTime(initialUserTrafficData.get(key)?.time),
        };
      });
    }
    return [];
  };

  const fetchV2BoardOrdersData = async (page = 1, pageSize = 10) => {
    const headers = { 'Authorization': `${CONFIG.V2BOARD_API_TOKEN}` };
    const url = `${CONFIG.V2BOARD_ORDERS_API_URL}?pageSize=${pageSize}&current=${page}`;
    return fetchApiData(url, "V2Board 訂單列表", 1, headers);
  };

  const fetchV2BoardOrderDetail = async (orderId) => {
    const headers = { 'Authorization': `${CONFIG.V2BOARD_API_TOKEN}` };
    return fetchApiData(CONFIG.V2BOARD_ORDER_DETAIL_API_URL, "V2Board 訂單詳情", 1, headers, 'POST', { id: orderId });
  };

  const fetchV2BoardUserInfo = async (userId) => {
    const headers = { 'Authorization': `${CONFIG.V2BOARD_API_TOKEN}` };
    const url = `${CONFIG.V2BOARD_USER_INFO_API_URL}?id=${userId}`;
    return fetchApiData(url, "V2Board 用戶信息", 1, headers);
  };

  const fetchAllData = async () => {
    sendMessage("status", "fetching");
    logMessage("開始數據獲取週期...", "info");

    fetchApiData(CONFIG.BALANCE_API_URL, "餘額").then(balanceResult => {
      sendMessage("balance_update", balanceResult);
      if(!balanceResult.error) logMessage("餘額數據已更新。", "success");
      else logMessage(`餘額數據更新失敗: ${balanceResult.details}`, "error");
    });

    // Fetch V2Board Override Data
    fetchV2BoardOverrideData().then(overrideResult => {
      sendMessage("v2board_override_update", overrideResult.data); // Send only the 'data' part
      if (!overrideResult.error) logMessage("V2Board 概覽數據已更新。", "success");
      else logMessage(`V2Board 概覽數據更新失敗: ${overrideResult.details}`, "error");
    });

    // Fetch V2Board Server Today Rank Data
    fetchV2BoardServerRankData(true).then(rankResult => {
      sendMessage("v2board_server_today_rank_update", rankResult);
      if (!rankResult.error) logMessage("V2Board 今日節點排行數據已更新。", "success");
      else logMessage(`V2Board 今日節點排行數據更新失敗: ${rankResult.details}`, "error");
    });

    // Fetch V2Board Server Last Rank Data
    fetchV2BoardServerRankData(false).then(rankResult => {
      sendMessage("v2board_server_last_rank_update", rankResult);
      if (!rankResult.error) logMessage("V2Board 昨日節點排行數據已更新。", "success");
      else logMessage(`V2Board 昨日節點排行數據更新失敗: ${rankResult.details}`, "error");
    });

    // Fetch V2Board User Today Rank Data
    fetchV2BoardUserRankData(true).then(rankResult => {
      sendMessage("v2board_user_today_rank_update", rankResult);
      if (!rankResult.error) logMessage("V2Board 今日用戶排行數據已更新。", "success");
      else logMessage(`V2Board 今日用戶排行數據更新失敗: ${rankResult.details}`, "error");
    });

    // Fetch V2Board User Last Rank Data
    fetchV2BoardUserRankData(false).then(rankResult => {
      sendMessage("v2board_user_last_rank_update", rankResult);
      if (!rankResult.error) logMessage("V2Board 昨日用戶排行數據已更新。", "success");
      else logMessage(`V2Board 昨日用戶排行數據更新失敗: ${rankResult.details}`, "error");
    });

    // Fetch recent 5 orders on initial load
    fetchApiData(`${CONFIG.ORDERS_API_URL}&page=1&limit=${CONFIG.DEFAULT_ORDERS_PER_PAGE}`, "訂單").then(ordersResult => {
      sendMessage("orders_update", { ...ordersResult, page: 1, limit: CONFIG.DEFAULT_ORDERS_PER_PAGE });
      if(!ordersResult.error) logMessage("最近訂單數據已更新。", "success");
      else logMessage(`最近訂單數據更新失敗: ${ordersResult.details}`, "error");
    });

    // Fetch V2Board orders
    fetchV2BoardOrdersData(1, 10).then(ordersResult => {
      sendMessage("v2board_orders_update", ordersResult);
      if(!ordersResult.error) logMessage("V2Board 訂單數據已更新。", "success");
      else logMessage(`V2Board 訂單數據更新失敗: ${ordersResult.details}`, "error");
    });

    let successfulFetches = 0;
    const trafficPromises = API_SOURCES.map(source =>
      fetchTrafficData(source).then(result => {
        sendMessage("traffic_update", result);
        if (!result.error) {
          successfulFetches++;
          logMessage(`${source.name} 的流量數據已更新。`, "success");
        } else {
          logMessage(`${source.name} 的流量數據獲取失敗: ${result.details}`, "warn");
        }
      })
    );

    await Promise.all(trafficPromises);
    logMessage(`獲取週期完成。 ${successfulFetches}/${API_SOURCES.length} 個流量來源成功。`, "info");
    sendMessage("status", "connected");
  };

  ws.addEventListener("message", async ({ data }) => {
    try {
      const msg = JSON.parse(data);
      if (!msg.action) return;

      switch (msg.action) {
        case "refreshAllData": // General refresh for all data (used on initial connect)
          await fetchAllData();
          break;

        case "refreshBalance": // Specific refresh for 91hk balance
          fetchApiData(CONFIG.BALANCE_API_URL, "餘額").then(balanceResult => {
            sendMessage("balance_update", balanceResult);
            if(!balanceResult.error) logMessage("餘額數據已更新。", "success");
            else logMessage(`餘額數據更新失敗: ${balanceResult.details}`, "error");
          });
          break;

        case "refreshV2boardOverride": // Specific refresh for V2Board Override
          fetchV2BoardOverrideData().then(overrideResult => {
            sendMessage("v2board_override_update", overrideResult.data);
            if (!overrideResult.error) logMessage("V2Board 概覽數據已更新。", "success");
            else logMessage(`V2Board 概覽數據更新失敗: ${overrideResult.details}`, "error");
          });
          break;

        case "refreshV2boardServerTodayRank": // Specific refresh for V2Board Server Today Rank
          fetchV2BoardServerRankData(true).then(rankResult => {
            sendMessage("v2board_server_today_rank_update", rankResult);
            if (!rankResult.error) logMessage("V2Board 今日節點排行數據已更新。", "success");
            else logMessage(`V2Board 今日節點排行數據更新失敗: ${rankResult.details}`, "error");
          });
          break;

        case "refreshV2boardUserTodayRank": // Specific refresh for V2Board User Today Rank
          fetchV2BoardUserRankData(true).then(rankResult => {
            sendMessage("v2board_user_today_rank_update", rankResult);
            if (!rankResult.error) logMessage("V2Board 今日用戶排行數據已更新。", "success");
            else logMessage(`V2Board 今日用戶排行數據更新失敗: ${rankResult.details}`, "error");
          });
          break;

        case "refreshAllTrafficData": // Refresh all traffic sources
          API_SOURCES.forEach(source => {
            fetchTrafficData(source).then(result => {
              sendMessage("traffic_update", result);
              if (!result.error) logMessage(`${source.name} 的流量數據已更新。`, "success");
              else logMessage(`${source.name} 的流量數據獲取失敗: ${result.details}`, "warn");
            });
          });
          break;

        case "fetchOrders":
          const { page = 1, limit = CONFIG.DEFAULT_ORDERS_PER_PAGE } = msg;
          logMessage(`正在獲取訂單數據 (頁碼: ${page}, 數量: ${limit})...`, "info");
          const ordersResult = await fetchApiData(`${CONFIG.ORDERS_API_URL}&page=${page}&limit=${limit}`, "訂單");
          sendMessage("orders_update", { ...ordersResult, page, limit });
          if(!ordersResult.error) logMessage("訂單數據已更新。", "success");
          else logMessage(`訂單數據更新失敗: ${ordersResult.details}`, "error");
          break;

        case "fetchSingleOrder":
          const { outTradeNo } = msg;
          logMessage(`正在獲取單個訂單數據 (訂單號: ${outTradeNo})...`, "info");
          const singleOrderResult = await fetchApiData(`${CONFIG.SINGLE_ORDER_API_URL}&out_trade_no=${outTradeNo}`, "單個訂單");
          sendMessage("single_order_update", singleOrderResult);
          if(!singleOrderResult.error) logMessage(`單個訂單數據 (訂單號: ${outTradeNo}) 已更新。`, "success");
          else logMessage(`單個訂單數據 (訂單號: ${outTradeNo}) 更新失敗: ${singleOrderResult.details}`, "error");
          break;

        case "fetchV2BoardOrders":
          const { v2page = 1, v2pageSize = 10 } = msg;
          logMessage(`正在獲取V2Board訂單數據 (頁碼: ${v2page}, 數量: ${v2pageSize})...`, "info");
          const v2boardOrdersResult = await fetchV2BoardOrdersData(v2page, v2pageSize);
          sendMessage("v2board_orders_update", v2boardOrdersResult);
          if(!v2boardOrdersResult.error) logMessage("V2Board 訂單數據已更新。", "success");
          else logMessage(`V2Board 訂單數據更新失敗: ${v2boardOrdersResult.details}`, "error");
          break;

        case "fetchV2BoardOrderDetail":
          const { orderId } = msg;
          logMessage(`正在獲取V2Board訂單詳情 (訂單ID: ${orderId})...`, "info");
          const v2boardOrderDetailResult = await fetchV2BoardOrderDetail(orderId);
          sendMessage("v2board_order_detail_update", v2boardOrderDetailResult);
          if(!v2boardOrderDetailResult.error) logMessage(`V2Board 訂單詳情 (訂單ID: ${orderId}) 已更新。`, "success");
          else logMessage(`V2Board 訂單詳情 (訂單ID: ${orderId}) 更新失敗: ${v2boardOrderDetailResult.details}`, "error");
          break;

        case "fetchV2BoardUserInfo":
          const { userId } = msg;
          logMessage(`正在獲取V2Board用戶信息 (用戶ID: ${userId})...`, "info");
          const v2boardUserInfoResult = await fetchV2BoardUserInfo(userId);
          sendMessage("v2board_user_info_update", v2boardUserInfoResult);
          if(!v2boardUserInfoResult.error) logMessage(`V2Board 用戶信息 (用戶ID: ${userId}) 已更新。`, "success");
          else logMessage(`V2Board 用戶信息 (用戶ID: ${userId}) 更新失敗: ${v2boardUserInfoResult.details}`, "error");
          break;
      }
    } catch (e) {
      logMessage(`處理消息時出錯: ${e.message}`, "error");
    }
  });

  ws.addEventListener("close", () => logMessage(`WebSocket 連線已關閉。`, "info"));
  ws.addEventListener("error", (e) => logMessage(`WebSocket 錯誤: ${e.message}`, "error"));

  logMessage(`WebSocket 會話已建立。`);
  fetchAllData(); // Initial data fetch on connection

  sendMessage("visitor_info", {
    ip: request.headers.get("cf-connecting-ip") || "N/A",
    city: request.headers.get("cf-ipcity") || "N/A",
    country: request.headers.get("cf-ipcountry") || "N/A",
  });
}

// ====================================================================================
// HTML 模板
// ====================================================================================

function getLoginHTML(isAuthenticated) {
  const frontendConfig = {
    ENABLE_TURNSTILE: CONFIG.ENABLE_TURNSTILE,
    TURNSTILE_SITE_KEY: CONFIG.TURNSTILE_SITE_KEY,
    IS_AUTHENTICATED: isAuthenticated, // Pass authentication status to frontend
  };

  return `<!DOCTYPE html>
<html lang="zh-CN" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>儀表板登入</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>:root { color-scheme: light; } html.dark { color-scheme: dark; }</style>
  <script>
    if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    tailwind.config = { darkMode: 'class' }
    window.__CONFIG__ = ${JSON.stringify(frontendConfig)};
  </script>
</head>
<body class="bg-gray-50 dark:bg-gray-900 font-sans transition-colors duration-300">
  <div id="app" class="flex items-center justify-center min-h-screen">
    <div class="bg-white dark:bg-gray-800 p-8 rounded-xl shadow-lg w-full max-w-sm border border-gray-200 dark:border-gray-700">
      <h2 class="text-2xl font-semibold mb-6 text-center text-gray-800 dark:text-gray-200">儀表板訪問</h2>
      <div class="space-y-5">
        <div id="auth-success-message" class="hidden bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded relative" role="alert">
          <strong class="font-bold">已驗證!</strong>
          <span class="block sm:inline">您已登入，即將自動跳轉。</span>
        </div>
        <input id="password" type="password" placeholder="請輸入密碼" class="w-full p-3 border rounded-lg bg-transparent focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all border-gray-300 dark:border-gray-600 text-gray-800 dark:text-gray-200">
        <div id="turnstile-container" style="display: none;">
          <div id="turnstile-widget"></div>
        </div>
        <p id="error-message" class="text-red-500 text-sm text-center h-5"></p>
        <button id="submit-button" class="w-full px-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-blue-400 disabled:cursor-wait transition-all">
          驗證並進入
        </button>
      </div>
    </div>
  </div>
  <script>
    const passwordInput = document.getElementById('password');
    const submitButton = document.getElementById('submit-button');
    const errorMessage = document.getElementById('error-message');
    const turnstileContainer = document.getElementById('turnstile-container');
    const authSuccessMessage = document.getElementById('auth-success-message');
    
    let turnstileWidgetId;

    window.onload = function() {
      if (window.__CONFIG__.ENABLE_TURNSTILE) {
        turnstileContainer.style.display = 'block';
        turnstileWidgetId = turnstile.render('#turnstile-widget', {
          sitekey: window.__CONFIG__.TURNSTILE_SITE_KEY,
          theme: document.documentElement.classList.contains('dark') ? 'dark' : 'light',
        });
      }

      if (window.__CONFIG__.IS_AUTHENTICATED) {
        authSuccessMessage.classList.remove('hidden');
        passwordInput.disabled = true;
        submitButton.disabled = true;
        submitButton.textContent = '已驗證，正在跳轉...';
        if (window.__CONFIG__.ENABLE_TURNSTILE) {
          turnstileContainer.style.display = 'none'; // Hide Turnstile if already authenticated
        }
        setTimeout(() => {
          window.location.href = '/dashboard';
        }, 2000); // Auto redirect after 2 seconds
      }
    };

    const handleLogin = async () => {
      submitButton.disabled = true;
      submitButton.textContent = '驗證中...';
      errorMessage.textContent = '';

      const password = passwordInput.value;
      let turnstileToken = '';

      if (window.__CONFIG__.ENABLE_TURNSTILE) {
        turnstileToken = turnstile.getResponse(turnstileWidgetId);
        if (!turnstileToken) {
          errorMessage.textContent = '請完成人機驗證。';
          submitButton.disabled = false;
          submitButton.textContent = '驗證並進入';
          return;
        }
      }

      if (!password) {
        errorMessage.textContent = '請輸入密碼。';
        submitButton.disabled = false;
        submitButton.textContent = '驗證並進入';
        return;
      }

      try {
        const response = await fetch('/api/auth', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password, turnstileToken }),
        });

        const result = await response.json();
        if (response.ok && result.success) {
          errorMessage.textContent = '驗證成功，正在跳轉...';
          authSuccessMessage.classList.remove('hidden'); // Show success message
          setTimeout(() => {
            window.location.href = '/dashboard';
          }, 1000); // Redirect faster after successful login
        } else {
          throw new Error(result.message || '未知錯誤');
        }
      } catch (err) {
        errorMessage.textContent = err.message;
        submitButton.disabled = false;
        submitButton.textContent = '驗證並進入';
        if (window.__CONFIG__.ENABLE_TURNSTILE) {
          turnstile.reset(turnstileWidgetId);
        }
      }
    };

    submitButton.addEventListener('click', handleLogin);
    passwordInput.addEventListener('keyup', (event) => { if (event.key === 'Enter') { handleLogin(); } });
  </script>
</body>
</html>`;
}

function getDashboardHTML() {
  const apiSourceNames = JSON.stringify(API_SOURCES.map(s => s.name));
  return `<!DOCTYPE html>
<html lang="zh-CN" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>即時儀表板</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css" rel="stylesheet">
  <script src="https://cdnjs.cloudflare.com/ajax/libs/vue/3.5.17/vue.global.prod.min.js"></script>
  <style>
    :root { color-scheme: light; }
    html.dark { color-scheme: dark; }
    body {
      --bg-color: #f9fafb; --text-color: #111827; --card-bg: #ffffff; --border-color: #e5e7eb;
      background-color: var(--bg-color); color: var(--text-color);
    }
    html.dark body {
      --bg-color: #111827; --text-color: #d1d5db; --card-bg: #1f2937; --border-color: #374151;
    }
    .card { background-color: var(--card-bg); border-color: var(--border-color); }
    .text-dim { color: #6b7280; }
    html.dark .text-dim { color: #9ca3af; }
    .skeleton { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; background-color: #e5e7eb; }
    html.dark .skeleton { background-color: #374151; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .5; } }
    
    /* Notification styles */
    .notification-container {
      position: fixed;
      top: 1rem;
      right: 1rem;
      z-index: 1000;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      max-width: 300px;
    }
    .notification {
      background-color: var(--card-bg);
      border: 1px solid var(--border-color);
      padding: 0.75rem 1rem;
      border-radius: 0.5rem;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      display: flex;
      align-items: center;
      gap: 0.75rem;
      opacity: 0;
      transform: translateY(-20px);
      animation: fadeInSlideDown 0.3s ease-out forwards;
    }
    .notification.fade-out {
      animation: fadeOutSlideUp 0.3s ease-in forwards;
    }
    .notification-icon {
      font-size: 1.25rem;
    }
    .notification-info .notification-icon { color: #3b82f6; } /* blue-500 */
    .notification-success .notification-icon { color: #22c55e; } /* green-500 */
    .notification-warn .notification-icon { color: #f59e0b; } /* yellow-500 */
    .notification-error .notification-icon { color: #ef4444; } /* red-500 */
    
    @keyframes fadeInSlideDown {
      from { opacity: 0; transform: translateY(-20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes fadeOutSlideUp {
      from { opacity: 1; transform: translateY(0); }
      to { opacity: 0; transform: translateY(-20px); }
    }
    
    /* Loading animation for buttons */
    .btn-loading {
      position: relative;
      color: transparent !important;
    }
    .btn-loading::after {
      content: "";
      position: absolute;
      width: 16px;
      height: 16px;
      top: 50%;
      left: 50%;
      margin-left: -8px;
      margin-top: -8px;
      border: 2px solid #ffffff;
      border-radius: 50%;
      border-top-color: transparent;
      animation: spinner 0.6s linear infinite;
    }
    @keyframes spinner {
      to { transform: rotate(360deg); }
    }
    
    /* User ID link style */
    .user-id-link {
      color: #3b82f6;
      text-decoration: underline;
      cursor: pointer;
    }
    .user-id-link:hover {
      color: #2563eb;
    }
    html.dark .user-id-link {
      color: #60a5fa;
    }
    html.dark .user-id-link:hover {
      color: #93bbfc;
    }
  </style>
  <script>
    if (localStorage.getItem('theme') === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    tailwind.config = { darkMode: 'class', theme: { extend: {} } }
  </script>
</head>
<body class="font-sans min-h-screen flex flex-col transition-colors duration-300">
  <div id="app" class="container mx-auto p-4 md:p-6 max-w-7xl flex-grow">
    <div class="space-y-6">
      <header class="flex flex-col md:flex-row justify-between items-center mb-4">
        <div>
          <h1 class="text-3xl font-bold">即時儀表板</h1>
          <p class="text-dim">服務即時監控狀態</p>
        </div>
        <div class="flex items-center gap-4 mt-4 md:mt-0">
          <span :class="statusPillClass" class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium shadow-sm transition-colors">
            <span class="w-2.5 h-2.5 mr-2 rounded-full" :class="statusDotClass"></span>
            {{ statusText }}
          </span>
          <button @click="toggleSettingsModal" class="text-dim hover:text-blue-500 transition-colors"><i class="fas fa-cog fa-lg"></i></button>
        </div>
      </header>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="lg:col-span-1 space-y-6">
          <div class="card border rounded-xl p-6 shadow-sm">
            <div class="flex justify-between items-center mb-4">
              <h2 class="text-lg font-semibold flex items-center"><i class="fas fa-wallet mr-3 text-dim"></i>帳戶資訊 (91hk)</h2>
              <button @click="refreshBalanceData" :disabled="isRefreshingBalance" class="text-dim hover:text-blue-500 transition-colors" :class="{'btn-loading': isRefreshingBalance}">
                <i :class="isRefreshingBalance ? 'fas fa-spinner invisible' : 'fas fa-sync-alt'"></i>
              </button>
            </div>
            <div v-if="!accountData && !accountError" class="space-y-4">
              <div class="skeleton h-5 w-3/4 rounded"></div><div class="skeleton h-5 w-1/2 rounded"></div><div class="skeleton h-5 w-2/3 rounded"></div>
            </div>
            <p v-if="accountError" class="text-red-400 text-sm">錯誤: {{ accountError.details || accountError.error }}</p>
            <div v-if="accountData" class="text-sm space-y-3">
              <div class="flex justify-between items-center"><span class="text-dim">餘額:</span><span class="font-semibold text-blue-400 text-base">{{ accountData.money }} CNY</span></div>
              <div class="flex justify-between items-center"><span class="text-dim">總訂單數:</span><span>{{ accountData.orders }}</span></div>
              <div class="flex justify-between items-center"><span class="text-dim">今日訂單數:</span><span>{{ accountData.orders_today }}</span></div>
            </div>
            <hr class="my-4 border-gray-200 dark:border-gray-700" />
            <div class="flex justify-between items-center mb-4">
              <h2 class="text-lg font-semibold flex items-center"><i class="fas fa-chart-line mr-3 text-dim"></i>帳戶概覽 (V2Board)</h2>
              <button @click="refreshV2boardOverrideData" :disabled="isRefreshingV2Override" class="text-dim hover:text-blue-500 transition-colors" :class="{'btn-loading': isRefreshingV2Override}">
                <i :class="isRefreshingV2Override ? 'fas fa-spinner invisible' : 'fas fa-sync-alt'"></i>
              </button>
            </div>
            <div v-if="!v2boardOverrideData && !v2boardOverrideError" class="space-y-4">
              <div class="skeleton h-5 w-3/4 rounded"></div><div class="skeleton h-5 w-1/2 rounded"></div><div class="skeleton h-5 w-2/3 rounded"></div>
            </div>
            <p v-if="v2boardOverrideError" class="text-red-400 text-sm">錯誤: {{ v2boardOverrideError.details || v2boardOverrideError.error }}</p>
            <div v-if="v2boardOverrideData" class="text-sm space-y-3">
              <div class="flex justify-between items-center"><span class="text-dim">線上用戶:</span><span>{{ v2boardOverrideData.online_user }}</span></div>
              <div class="flex justify-between items-center"><span class="text-dim">本月收入:</span><span class="font-semibold text-green-400 text-base">{{ (v2boardOverrideData.month_income / 100).toFixed(2) }} CNY</span></div>
              <div class="flex justify-between items-center"><span class="text-dim">今日收入:</span><span>{{ (v2boardOverrideData.day_income / 100).toFixed(2) }} CNY</span></div>
              <div class="flex justify-between items-center"><span class="text-dim">上月收入:</span><span>{{ (v2boardOverrideData.last_month_income / 100).toFixed(2) }} CNY</span></div>
              <div class="flex justify-between items-center"><span class="text-dim">本月佣金支出:</span><span>{{ (v2boardOverrideData.commission_month_payout / 100).toFixed(2) }} CNY</span></div>
              <div class="flex justify-between items-center"><span class="text-dim">上月佣金支出:</span><span>{{ (v2boardOverrideData.commission_last_month_payout / 100).toFixed(2) }} CNY</span></div>
              <div class="flex justify-between items-center"><span class="text-dim">本月註冊數:</span><span>{{ v2boardOverrideData.month_register_total }}</span></div>
            </div>
          </div>

          <div class="card border rounded-xl p-6 shadow-sm">
            <h2 class="text-lg font-semibold mb-4 flex items-center"><i class="fas fa-search mr-3 text-dim"></i>訂單搜尋</h2>
            <div class="flex gap-2">
              <input v-model="singleOrderInput" type="text" placeholder="請輸入訂單號" class="w-full p-2 border rounded-lg bg-transparent focus:outline-none focus:ring-2 focus:ring-blue-500 card">
              <button @click="fetchSingleOrderDetails" :disabled="!singleOrderInput || isFetchingSingleOrder" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 whitespace-nowrap" :class="{'btn-loading': isFetchingSingleOrder}">
                <i :class="isFetchingSingleOrder ? 'fas fa-search invisible' : 'fas fa-search'"></i>
              </button>
            </div>
          </div>

          <div class="card border rounded-xl p-6 shadow-sm">
            <div class="flex justify-between items-center mb-4">
              <h2 class="text-lg font-semibold flex items-center"><i class="fas fa-receipt mr-3 text-dim"></i>最近訂單 ({{ DEFAULT_ORDERS_PER_PAGE }}條)</h2>
              <button @click="fetchBatchOrders" :disabled="isFetchingOrders" class="text-dim hover:text-blue-500 transition-colors" :class="{'btn-loading': isFetchingOrders}">
                <i :class="isFetchingOrders ? 'fas fa-spinner invisible' : 'fas fa-sync-alt'"></i>
              </button>
            </div>
            <div v-if="!ordersList && !ordersError" class="space-y-3">
              <div v-for="i in 3" :key="i" class="skeleton h-10 w-full rounded-lg"></div>
            </div>
            <p v-if="ordersError" class="text-red-400 text-sm">錯誤: {{ ordersError.details || ordersError.error }}</p>
            <div v-if="ordersList?.orders?.length" class="text-xs space-y-3 max-h-96 overflow-y-auto pr-2">
              <div v-for="order in ordersList.orders" :key="order.trade_no" class="p-3 rounded-lg flex justify-between items-center card border">
                <div>
                  <p class="font-semibold">{{ order.name }}</p>
                  <p class="text-dim">{{ order.out_trade_no }}</p>
                  <p>{{ order.money }} CNY - <span :class="order.status === '1' ? 'text-green-400' : 'text-yellow-400'">{{ order.status === '1' ? '已支付' : '未支付' }}</span></p>
                </div>
                <button @click="viewOrderDetails(order.out_trade_no)" class="px-3 py-1 bg-gray-500 dark:bg-gray-600 text-white rounded-md hover:bg-gray-700 text-xs">查看</button>
              </div>
            </div>
            <p v-else-if="!ordersError" class="text-dim text-center py-4">沒有找到任何訂單。</p>
          </div>
        </div>

        <div class="lg:col-span-2 space-y-6">
          <div class="card border rounded-xl p-6 shadow-sm">
            <div class="flex justify-between items-center mb-4">
              <h2 class="text-lg font-semibold flex items-center"><i class="fas fa-network-wired mr-3 text-dim"></i>流量總覽</h2>
              <button @click="refreshAllTrafficData" :disabled="isRefreshingTraffic" class="text-dim hover:text-blue-500 transition-colors" :class="{'btn-loading': isRefreshingTraffic}">
                <i :class="isRefreshingTraffic ? 'fas fa-spinner invisible' : 'fas fa-sync-alt'"></i>
              </button>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div v-for="data in trafficData" :key="data.sourceName" class="card border rounded-xl p-4 shadow-sm">
                <div class="flex justify-between items-center mb-2">
                  <h3 class="font-semibold text-base">{{ data.sourceName }}</h3>
                </div>
                <div v-if="data.isLoading" class="space-y-3">
                  <div class="skeleton h-2 w-full rounded-full"></div>
                  <div class="skeleton h-4 w-3/4 rounded mt-2"></div>
                  <div class="skeleton h-4 w-2/3 rounded"></div>
                  <div class="skeleton h-4 w-1/2 rounded"></div>
                </div>
                <div v-else-if="data.error" class="text-red-400">
                  <p class="text-sm"><strong>錯誤:</strong> {{ data.details || data.error }}</p>
                </div>
                <div v-else class="space-y-2 text-xs">
                  <div class="flex justify-between items-center"><span class="text-dim">用量</span> <div class="flex justify-between text-dim"><span>(U: {{ formatTraffic(data.upload) }} / D: {{ formatTraffic(data.download) }})</span></div><span :class="data.usagePercent >= 90 ? 'text-red-400 font-bold' : (data.usagePercent >= 75 ? 'text-yellow-400' : 'text-green-400')">{{ data.usagePercent }}%</span></div>
                  <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5"><div :class="data.usagePercent >= 90 ? 'bg-red-500' : (data.usagePercent >= 75 ? 'bg-yellow-500' : 'bg-green-500')" class="h-1.5 rounded-full" :style="{ width: data.usagePercent + '%' }"></div></div>
                  <div class="pt-2 space-y-1">
                    <div class="flex justify-between"><span>總量:</span><span>{{ formatTraffic(data.total) }}</span></div>
                    <div class="flex justify-between"><span>已用:</span><span>{{ formatTraffic(data.upload + data.download) }}</span></div>
                    <div class="flex justify-between"><span>剩余:</span><span>{{ formatTraffic(data.total - (data.upload + data.download)) }}</span></div>
                    <div class="flex justify-between"><span>運行期間使用:</span></div>
                    <div class="flex justify-between text-dim"><span>{{ formatTraffic(data.runtimeTotal) }} (U: {{ formatTraffic(data.runtimeUpload) }} / D: {{ formatTraffic(data.runtimeDownload) }})</span></div>
                    <div class="flex justify-between"><span>過期時間:</span><span>{{ data.expiry }}</span></div>
                    <div class="flex justify-between"><span>運行時間:</span><span>{{ data.elapsedTime }}</span></div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="card border rounded-xl p-6 shadow-sm">
            <div class="flex justify-between items-center mb-4">
              <h2 class="text-lg font-semibold flex items-center"><i class="fas fa-file-invoice mr-3 text-dim"></i>V2Board 訂單列表</h2>
              <button @click="fetchV2BoardOrders" :disabled="isFetchingV2BoardOrders" class="text-dim hover:text-blue-500 transition-colors" :class="{'btn-loading': isFetchingV2BoardOrders}">
                <i :class="isFetchingV2BoardOrders ? 'fas fa-spinner invisible' : 'fas fa-sync-alt'"></i>
              </button>
            </div>
            <div v-if="!v2boardOrdersList && !v2boardOrdersError" class="space-y-3">
              <div v-for="i in 5" :key="i" class="skeleton h-16 w-full rounded-lg"></div>
            </div>
            <p v-if="v2boardOrdersError" class="text-red-400 text-sm">錯誤: {{ v2boardOrdersError.details || v2boardOrdersError.error }}</p>
            <div v-if="v2boardOrdersList?.data?.length" class="text-xs space-y-3 max-h-96 overflow-y-auto pr-2">
              <div v-for="order in v2boardOrdersList.data" :key="order.id" class="p-3 rounded-lg card border">
                <div class="flex justify-between items-center">
                  <div class="flex-1">
                    <div class="flex items-center gap-2 mb-1">
                      <p class="font-semibold">{{ order.plan_name }} - {{ getPeriodText(order.period) }}</p>
                      <span :class="getOrderStatusClass(order.status)" class="text-xs px-2 py-0.5 rounded">{{ getOrderStatusText(order.status) }}</span>
                    </div>
                    <p class="text-dim">訂單號: {{ order.trade_no }}</p>
                    <p>金額: {{ (order.total_amount / 100).toFixed(2) }} CNY</p>
                    <p class="text-dim">用戶ID: <a @click.stop="viewUserInfo(order.user_id)" class="user-id-link">{{ order.user_id }}</a></p>
                    <p class="text-dim">{{ formatTimestamp(order.created_at) }}</p>
                  </div>
                  <button @click="viewV2BoardOrderDetails(order.id)" class="px-3 py-1 bg-gray-500 dark:bg-gray-600 text-white rounded-md hover:bg-gray-700 text-xs ml-2">查看</button>
                </div>
              </div>
            </div>
            <p v-else-if="!v2boardOrdersError" class="text-dim text-center py-4">沒有找到任何訂單。</p>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="card border rounded-xl p-6 shadow-sm">
              <div class="flex justify-between items-center mb-4">
                <h2 class="text-lg font-semibold flex items-center"><i class="fas fa-server mr-3 text-dim"></i>今日節點流量排行</h2>
                <button @click="refreshV2boardServerTodayRank" :disabled="isRefreshingServerToday" class="text-dim hover:text-blue-500 transition-colors" :class="{'btn-loading': isRefreshingServerToday}">
                  <i :class="isRefreshingServerToday ? 'fas fa-spinner invisible' : 'fas fa-sync-alt'"></i>
                </button>
              </div>
              <div v-if="!v2boardServerTodayRank || v2boardServerTodayRank.length === 0" class="text-dim text-center py-4">沒有數據。</div>
              <div v-else class="space-y-3 text-xs max-h-96 overflow-y-auto pr-2">
                <div v-for="server in v2boardServerTodayRank" :key="server.server_id" class="p-3 rounded-lg flex justify-between items-center card border">
                  <div>
                    <p class="font-semibold">{{ server.server_name }}（ID: {{ server.server_id }}）</p>
                    <p class="text-dim">總流量: {{ formatTraffic(server.total * 1024 * 1024 * 1024) }}</p>
                    <p class="text-dim">上傳: {{ formatTraffic(server.u) }} / 下載: {{ formatTraffic(server.d) }}</p>
                    <p class="text-dim">運行期間使用: {{ formatTraffic(server.runtimeTotal) }} (U: {{ formatTraffic(server.runtimeUpload) }} / D: {{ formatTraffic(server.runtimeDownload) }})</p>
                  </div>
                </div>
              </div>
            </div>

            <div class="card border rounded-xl p-6 shadow-sm">
              <div class="flex justify-between items-center mb-4">
                <h2 class="text-lg font-semibold flex items-center"><i class="fas fa-server mr-3 text-dim"></i>昨日節點流量排行</h2>
              </div>
              <div v-if="!v2boardServerLastRank || v2boardServerLastRank.length === 0" class="text-dim text-center py-4">沒有數據。</div>
              <div v-else class="space-y-3 text-xs max-h-96 overflow-y-auto pr-2">
                <div v-for="server in v2boardServerLastRank" :key="server.server_id" class="p-3 rounded-lg flex justify-between items-center card border">
                  <div>
                    <p class="font-semibold">{{ server.server_name }}（ID: {{ server.server_id }}）</p>
                    <p class="text-dim">總流量: {{ formatTraffic(server.total * 1024 * 1024 * 1024) }}</p>
                    <p class="text-dim">上傳: {{ formatTraffic(server.u) }} / 下載: {{ formatTraffic(server.d) }}</p>
                    <p class="text-dim">運行期間使用: {{ formatTraffic(server.runtimeTotal) }} (U: {{ formatTraffic(server.runtimeUpload) }} / D: {{ formatTraffic(server.runtimeDownload) }})</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="card border rounded-xl p-6 shadow-sm">
              <div class="flex justify-between items-center mb-4">
                <h2 class="text-lg font-semibold flex items-center"><i class="fas fa-users mr-3 text-dim"></i>今日用戶流量排行</h2>
                <button @click="refreshV2boardUserTodayRank" :disabled="isRefreshingUserToday" class="text-dim hover:text-blue-500 transition-colors" :class="{'btn-loading': isRefreshingUserToday}">
                  <i :class="isRefreshingUserToday ? 'fas fa-spinner invisible' : 'fas fa-sync-alt'"></i>
                </button>
              </div>
              <div v-if="!v2boardUserTodayRank || v2boardUserTodayRank.length === 0" class="text-dim text-center py-4">沒有數據。</div>
              <div v-else class="space-y-3 text-xs max-h-96 overflow-y-auto pr-2">
                <div v-for="user in v2boardUserTodayRank" :key="user.user_id" class="p-3 rounded-lg flex justify-between items-center card border">
                  <div>
                    <p class="font-semibold">{{ user.email }} <span class="text-dim">(ID: <a @click.stop="viewUserInfo(user.user_id)" class="user-id-link">{{ user.user_id }}</a>)</span></p>
                    <p class="text-dim">總流量: {{ formatTraffic(user.total * 1024 * 1024 * 1024) }}</p>
                    <p class="text-dim">上傳: {{ formatTraffic(user.u) }} / 下載: {{ formatTraffic(user.d) }}</p>
                    <p class="text-dim">運行期間使用: {{ formatTraffic(user.runtimeTotal) }} (U: {{ formatTraffic(user.runtimeUpload) }} / D: {{ formatTraffic(user.runtimeDownload) }})</p>
                  </div>
                </div>
              </div>
            </div>

            <div class="card border rounded-xl p-6 shadow-sm">
              <div class="flex justify-between items-center mb-4">
                <h2 class="text-lg font-semibold flex items-center"><i class="fas fa-users mr-3 text-dim"></i>昨日用戶流量排行</h2>
              </div>
              <div v-if="!v2boardUserLastRank || v2boardUserLastRank.length === 0" class="text-dim text-center py-4">沒有數據。</div>
              <div v-else class="space-y-3 text-xs max-h-96 overflow-y-auto pr-2">
                <div v-for="user in v2boardUserLastRank" :key="user.user_id" class="p-3 rounded-lg flex justify-between items-center card border">
                  <div>
                    <p class="font-semibold">{{ user.email }} <span class="text-dim">(ID: <a @click.stop="viewUserInfo(user.user_id)" class="user-id-link">{{ user.user_id }}</a>)</span></p>
                    <p class="text-dim">總流量: {{ formatTraffic(user.total * 1024 * 1024 * 1024) }}</p>
                    <p class="text-dim">上傳: {{ formatTraffic(user.u) }} / 下載: {{ formatTraffic(user.d) }}</p>
                    <p class="text-dim">運行期間使用: {{ formatTraffic(user.runtimeTotal) }} (U: {{ formatTraffic(user.runtimeUpload) }} / D: {{ formatTraffic(user.runtimeDownload) }})</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div class="card border rounded-xl p-6 shadow-sm">
            <div class="flex justify-between items-center mb-4">
              <h2 class="text-lg font-semibold flex items-center"><i class="fas fa-terminal mr-3 text-dim"></i>系統日誌</h2>
              <button @click="systemLogs = []" class="text-dim hover:text-blue-500 transition-colors"><i class="fas fa-trash-alt"></i></button>
            </div>
            <div class="p-3 max-h-60 overflow-y-auto font-mono text-xs bg-gray-100 dark:bg-gray-800 rounded-lg">
              <div v-for="(log, index) in systemLogs" :key="index" class="flex gap-3 mb-1" :class="log.class">
                <span class="text-gray-500 flex-shrink-0">{{ log.timestamp }}</span>
                <span>{{ log.message }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <footer class="text-center mt-8 text-dim text-sm py-4">
        <p v-if="visitorDetails.ip">您的 IP: {{ visitorDetails.ip }} | 地點: {{ visitorDetails.country }}</p>
        <p>由 Cloudflare Workers 驅動</p>
      </footer>

      <div v-if="isSettingsModalOpen" @click.self="toggleSettingsModal" class="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4">
        <div class="card border rounded-xl shadow-lg w-full max-w-md p-6">
          <h2 class="text-lg font-semibold mb-6">設定</h2>
          <div class="space-y-4">
            <h3 class="font-semibold text-sm border-b border-gray-300 dark:border-gray-600 pb-2">UI 設定</h3>
            <div class="flex justify-between items-center">
              <label for="darkModeToggle">暗黑模式</label>
              <button @click="toggleTheme" class="px-4 py-2 rounded-lg text-sm" :class="isDark ? 'bg-yellow-400 text-gray-900' : 'bg-gray-700 text-white'">
                <i :class="isDark ? 'fas fa-sun' : 'fas fa-moon'"></i> {{ isDark ? '明亮' : '暗黑' }}
              </button>
            </div>
            <div class="flex justify-end pt-4 border-t border-gray-300 dark:border-gray-600">
              <button @click="handleLogout" class="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors">
                <i class="fas fa-sign-out-alt mr-2"></i>登出
              </button>
            </div>
          </div>
          <div class="mt-6 flex justify-end">
            <button @click="toggleSettingsModal" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">關閉</button>
          </div>
        </div>
      </div>

      <div v-if="isOrderDetailsModalOpen" @click.self="isOrderDetailsModalOpen = false" class="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4">
        <div class="card border rounded-xl shadow-lg w-full max-w-lg p-6">
          <h2 class="text-lg font-semibold mb-4">訂單詳情</h2>
          <div v-if="isFetchingSingleOrder" class="flex justify-center items-center h-48"><i class="fas fa-spinner fa-2x animate-spin text-dim"></i></div>
          <p v-else-if="singleOrderError" class="text-red-400">錯誤: {{ singleOrderError.details || singleOrderError.error }}</p>
          <div v-else-if="singleOrderDetails" class="text-sm space-y-2">
            <div class="grid grid-cols-3 gap-2">
              <span class="text-dim col-span-1">易支付訂單號:</span><span class="col-span-2 font-mono break-all">{{ singleOrderDetails.trade_no || 'N/A' }}</span>
              <span class="text-dim col-span-1">商戶訂單號:</span><span class="col-span-2 font-mono break-all">{{ singleOrderDetails.out_trade_no || 'N/A' }}</span>
              <span class="text-dim col-span-1">第三方訂單號:</span><span class="col-span-2 font-mono break-all">{{ singleOrderDetails.api_trade_no || 'N/A' }}</span>
              <span class="text-dim col-span-1">狀態:</span><span class="col-span-2" :class="singleOrderDetails.status === '1' ? 'text-green-400' : 'text-yellow-400'">{{ singleOrderDetails.status === '1' ? '已支付' : '未支付' }}</span>
              <span class="text-dim col-span-1">金額:</span><span class="col-span-2">{{ singleOrderDetails.money }} CNY</span>
              <span class="text-dim col-span-1">支付方式:</span><span class="col-span-2">{{ singleOrderDetails.type || 'N/A' }}</span>
              <span class="text-dim col-span-1">商品名稱:</span><span class="col-span-2">{{ singleOrderDetails.name || 'N/A' }}</span>
              <span class="text-dim col-span-1">商戶ID:</span><span class="col-span-2">{{ singleOrderDetails.pid || 'N/A' }}</span>
              <span class="text-dim col-span-1">創建時間:</span><span class="col-span-2">{{ singleOrderDetails.addtime || 'N/A' }}</span>
              <span class="text-dim col-span-1">完成時間:</span><span class="col-span-2">{{ singleOrderDetails.endtime || 'N/A' }}</span>
              <span class="text-dim col-span-1">業務擴展參數:</span><span class="col-span-2 break-all">{{ singleOrderDetails.param || 'N/A' }}</span>
              <span class="text-dim col-span-1">支付者賬號:</span><span class="col-span-2 break-all">{{ singleOrderDetails.buyer || 'N/A' }}</span>
            </div>
          </div>
          <div class="mt-6 flex justify-end">
            <button @click="isOrderDetailsModalOpen = false" class="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700">關閉</button>
          </div>
        </div>
      </div>

      <div v-if="isV2BoardOrderDetailsModalOpen" @click.self="isV2BoardOrderDetailsModalOpen = false" class="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4">
        <div class="card border rounded-xl shadow-lg w-full max-w-lg p-6">
          <h2 class="text-lg font-semibold mb-4">V2Board 訂單詳情</h2>
          <div v-if="isFetchingV2BoardOrderDetail" class="flex justify-center items-center h-48"><i class="fas fa-spinner fa-2x animate-spin text-dim"></i></div>
          <p v-else-if="v2boardOrderDetailError" class="text-red-400">錯誤: {{ v2boardOrderDetailError.details || v2boardOrderDetailError.error }}</p>
          <div v-else-if="v2boardOrderDetail" class="text-sm space-y-2">
            <div class="grid grid-cols-3 gap-2">
              <span class="text-dim col-span-1">訂單ID:</span><span class="col-span-2">{{ v2boardOrderDetail.id }}</span>
              <span class="text-dim col-span-1">訂單號:</span><span class="col-span-2 font-mono break-all">{{ v2boardOrderDetail.trade_no }}</span>
              <span class="text-dim col-span-1">用戶ID:</span><span class="col-span-2"><a @click.stop="viewUserInfo(v2boardOrderDetail.user_id)" class="user-id-link">{{ v2boardOrderDetail.user_id }}</a></span>
              <span class="text-dim col-span-1">套餐:</span><span class="col-span-2">{{ v2boardOrderDetail.plan_name || 'N/A' }} (ID: {{ v2boardOrderDetail.plan_id }})</span>
              <span class="text-dim col-span-1">類型:</span><span class="col-span-2">{{ getOrderTypeText(v2boardOrderDetail.type) }}</span>
              <span class="text-dim col-span-1">週期:</span><span class="col-span-2">{{ getPeriodText(v2boardOrderDetail.period) }}</span>
              <span class="text-dim col-span-1">狀態:</span><span class="col-span-2" :class="getOrderStatusClass(v2boardOrderDetail.status)">{{ getOrderStatusText(v2boardOrderDetail.status) }}</span>
              <span class="text-dim col-span-1">總金額:</span><span class="col-span-2">{{ (v2boardOrderDetail.total_amount / 100).toFixed(2) }} CNY</span>
              <span class="text-dim col-span-1">佣金狀態:</span><span class="col-span-2">{{ getCommissionStatusText(v2boardOrderDetail.commission_status) }}</span>
              <span class="text-dim col-span-1">佣金金額:</span><span class="col-span-2">{{ (v2boardOrderDetail.commission_balance / 100).toFixed(2) }} CNY</span>
              <span class="text-dim col-span-1">支付時間:</span><span class="col-span-2">{{ formatTimestamp(v2boardOrderDetail.paid_at) }}</span>
              <span class="text-dim col-span-1">創建時間:</span><span class="col-span-2">{{ formatTimestamp(v2boardOrderDetail.created_at) }}</span>
              <span class="text-dim col-span-1">更新時間:</span><span class="col-span-2">{{ formatTimestamp(v2boardOrderDetail.updated_at) }}</span>
              <span class="text-dim col-span-1">回調單號:</span><span class="col-span-2 font-mono break-all">{{ v2boardOrderDetail.callback_no || 'N/A' }}</span>
            </div>
          </div>
          <div class="mt-6 flex justify-end">
            <button @click="isV2BoardOrderDetailsModalOpen = false" class="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700">關閉</button>
          </div>
        </div>
      </div>

      <div v-if="isUserInfoModalOpen" @click.self="isUserInfoModalOpen = false" class="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 p-4">
        <div class="card border rounded-xl shadow-lg w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
          <h2 class="text-lg font-semibold mb-4">用戶詳細信息</h2>
          <div v-if="isFetchingUserInfo" class="flex justify-center items-center h-48"><i class="fas fa-spinner fa-2x animate-spin text-dim"></i></div>
          <p v-else-if="userInfoError" class="text-red-400">錯誤: {{ userInfoError.details || userInfoError.error }}</p>
          <div v-else-if="userInfo" class="text-sm space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div class="space-y-2">
                <h3 class="font-semibold text-base mb-2">基本信息</h3>
                <div class="space-y-1">
                  <p><span class="text-dim">用戶ID:</span> {{ userInfo.id }}</p>
                  <p><span class="text-dim">郵箱:</span> {{ userInfo.email }}</p>
                  <p><span class="text-dim">UUID:</span> <span class="font-mono text-xs">{{ userInfo.uuid }}</span></p>
                  <p><span class="text-dim">狀態:</span> <span :class="userInfo.banned ? 'text-red-400' : 'text-green-400'">{{ userInfo.banned ? '已封禁' : '正常' }}</span></p>
                  <p><span class="text-dim">餘額:</span> {{ (userInfo.balance / 100).toFixed(2) }} CNY</p>
                  <p><span class="text-dim">佣金餘額:</span> {{ (userInfo.commission_balance / 100).toFixed(2) }} CNY</p>
                </div>
              </div>
              <div class="space-y-2">
                <h3 class="font-semibold text-base mb-2">套餐信息</h3>
                <div class="space-y-1">
                  <p><span class="text-dim">當前套餐ID:</span> {{ userInfo.plan_id || 'N/A' }}</p>
                  <p><span class="text-dim">組ID:</span> {{ userInfo.group_id || 'N/A' }}</p>
                  <p><span class="text-dim">設備限制:</span> {{ userInfo.device_limit || '無限制' }}</p>
                  <p><span class="text-dim">速度限制:</span> {{ userInfo.speed_limit ? userInfo.speed_limit + ' Mbps' : '無限制' }}</p>
                  <p><span class="text-dim">到期時間:</span> {{ formatTimestamp(userInfo.expired_at) }}</p>
                </div>
              </div>
            </div>
            <div class="space-y-2">
              <h3 class="font-semibold text-base mb-2">流量信息</h3>
              <div class="space-y-1">
                <p><span class="text-dim">總流量:</span> {{ formatTraffic(userInfo.transfer_enable) }}</p>
                <p><span class="text-dim">已上傳:</span> {{ formatTraffic(userInfo.u) }}</p>
                <p><span class="text-dim">已下載:</span> {{ formatTraffic(userInfo.d) }}</p>
                <p><span class="text-dim">已使用:</span> {{ formatTraffic(userInfo.u + userInfo.d) }} ({{ ((userInfo.u + userInfo.d) / userInfo.transfer_enable * 100).toFixed(2) }}%)</p>
                <p><span class="text-dim">剩餘流量:</span> {{ formatTraffic(userInfo.transfer_enable - userInfo.u - userInfo.d) }}</p>
              </div>
              <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mt-2">
                <div :class="((userInfo.u + userInfo.d) / userInfo.transfer_enable * 100) >= 90 ? 'bg-red-500' : (((userInfo.u + userInfo.d) / userInfo.transfer_enable * 100) >= 75 ? 'bg-yellow-500' : 'bg-green-500')" 
                     class="h-2 rounded-full transition-all" 
                     :style="{ width: Math.min(((userInfo.u + userInfo.d) / userInfo.transfer_enable * 100), 100) + '%' }">
                </div>
              </div>
            </div>
            <div class="space-y-2">
              <h3 class="font-semibold text-base mb-2">其他信息</h3>
              <div class="space-y-1">
                <p><span class="text-dim">註冊時間:</span> {{ formatTimestamp(userInfo.created_at) }}</p>
                <p><span class="text-dim">最後登錄:</span> {{ formatTimestamp(userInfo.last_login_at) }}</p>
                <p><span class="text-dim">最後更新:</span> {{ formatTimestamp(userInfo.updated_at) }}</p>
                <p><span class="text-dim">訂閱更新時間:</span> {{ formatTimestamp(userInfo.subup_at) }}</p>
                <p><span class="text-dim">邀請人ID:</span> {{ userInfo.invite_user_id || '無' }}</p>
                <p><span class="text-dim">佣金類型:</span> {{ userInfo.commission_type === 0 ? '系統默認' : '自定義' }}</p>
                <p v-if="userInfo.commission_rate"><span class="text-dim">佣金比例:</span> {{ userInfo.commission_rate }}%</p>
                <p><span class="text-dim">提醒設置:</span> 
                  <span v-if="userInfo.remind_expire">到期提醒</span>
                  <span v-if="userInfo.remind_expire && userInfo.remind_traffic">, </span>
                  <span v-if="userInfo.remind_traffic">流量提醒</span>
                  <span v-if="!userInfo.remind_expire && !userInfo.remind_traffic">無</span>
                </p>
              </div>
            </div>
          </div>
          <div class="mt-6 flex justify-end">
            <button @click="isUserInfoModalOpen = false" class="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700">關閉</button>
          </div>
        </div>
      </div>
    </div>

    <div class="notification-container">
      <div v-for="(notification, index) in notifications" :key="index" 
           :class="['notification', 'shadow-md', 'flex', 'items-center', 'gap-3', 'text-sm', \`notification-\${notification.type}\`, { 'fade-out': notification.fadeOut }]" 
           :style="{ 'animation-delay': notification.delay + 's' }">
        <i class="notification-icon" :class="getNotificationIcon(notification.type)"></i>
        <div>
          <p class="font-semibold">{{ notification.message }}</p>
        </div>
      </div>
    </div>
  </div>

  <script type="module">
    const { createApp, ref, computed, onMounted, onUnmounted } = Vue;

    createApp({
      setup() {
        const webSocket = ref(null);
        const connectionStatus = ref("connecting");
        const reconnectAttempts = ref(0);
        const accountData = ref(null);
        const accountError = ref(null);
        const v2boardOverrideData = ref(null);
        const v2boardOverrideError = ref(null);
        const v2boardServerTodayRank = ref([]);
        const v2boardServerLastRank = ref([]);
        const v2boardUserTodayRank = ref([]);
        const v2boardUserLastRank = ref([]);
        const ordersList = ref(null);
        const ordersError = ref(null);
        const isFetchingOrders = ref(false);
        const singleOrderInput = ref("");
        const singleOrderDetails = ref(null);
        const singleOrderError = ref(null);
        const isFetchingSingleOrder = ref(false);
        const isOrderDetailsModalOpen = ref(false);
        const trafficData = ref(${apiSourceNames}.map(name => ({ sourceName: name, isLoading: true })));
        const systemLogs = ref([]);
        const notifications = ref([]);
        const notificationIdCounter = ref(0); // For unique notification keys
        const DEFAULT_ORDERS_PER_PAGE = ${CONFIG.DEFAULT_ORDERS_PER_PAGE};
        const visitorDetails = ref({});
        const isSettingsModalOpen = ref(false);
        const isDark = ref(document.documentElement.classList.contains('dark'));
        
        // V2Board orders
        const v2boardOrdersList = ref(null);
        const v2boardOrdersError = ref(null);
        const isFetchingV2BoardOrders = ref(false);
        const v2boardOrderDetail = ref(null);
        const v2boardOrderDetailError = ref(null);
        const isFetchingV2BoardOrderDetail = ref(false);
        const isV2BoardOrderDetailsModalOpen = ref(false);
        
        // User info
        const userInfo = ref(null);
        const userInfoError = ref(null);
        const isFetchingUserInfo = ref(false);
        const isUserInfoModalOpen = ref(false);
        
        // Refresh states
        const isRefreshingBalance = ref(false);
        const isRefreshingV2Override = ref(false);
        const isRefreshingTraffic = ref(false);
        const isRefreshingServerToday = ref(false);
        const isRefreshingUserToday = ref(false);

        const statusInfo = computed(() => ({
          connecting: { text: "連線中...", pill: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300", dot: "bg-blue-500 animate-pulse" },
          connected: { text: "已連線", pill: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300", dot: "bg-green-500" },
          disconnected: { text: "已斷線", pill: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300", dot: "bg-red-500" },
          fetching: { text: "獲取數據中...", pill: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300", dot: "bg-yellow-500 animate-spin" },
        }[connectionStatus.value]));

        const statusText = computed(() => statusInfo.value.text);
        const statusPillClass = computed(() => statusInfo.value.pill);
        const statusDotClass = computed(() => statusInfo.value.dot);

        const addLog = (message, type = "info") => {
          const logMap = { info: "text-blue-400", success: "text-green-400", warn: "text-yellow-400", error: "text-red-400" };
          const timestamp = new Date().toLocaleTimeString("en-GB");
          systemLogs.value.unshift({ message, type, class: logMap[type], timestamp });
          if (systemLogs.value.length > ${CONFIG.MAX_LOGS}) systemLogs.value.pop();
        };

        const addNotification = (message, type = "info", duration = 5000) => {
          const id = notificationIdCounter.value++;
          const newNotification = { id, message, type, fadeOut: false, delay: 0 };
          notifications.value.unshift(newNotification);
          setTimeout(() => {
            newNotification.fadeOut = true;
            setTimeout(() => {
              notifications.value = notifications.value.filter(n => n.id !== id);
            }, 300); // Should match fadeOut animation duration
          }, duration);
        };

        const getNotificationIcon = (type) => {
          switch (type) {
            case 'info': return 'fas fa-info-circle';
            case 'success': return 'fas fa-check-circle';
            case 'warn': return 'fas fa-exclamation-triangle';
            case 'error': return 'fas fa-times-circle';
            default: return 'fas fa-info-circle';
          }
        };

        const formatTraffic = (bytes) => {
          if (bytes == null || isNaN(bytes)) return "N/A";
          const units = ["B", "KB", "MB", "GB", "TB"];
          let value = parseInt(bytes);
          let i = 0;
          while (value >= 1024 && i < units.length - 1) {
            value /= 1024;
            i++;
          }
          return \`\${value.toFixed(1)} \${units[i]}\`;
        };

        const formatTimestamp = (timestamp) => {
          if (!timestamp || isNaN(timestamp)) return "N/A";
          return new Date(parseInt(timestamp) * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" });
        };

        const getOrderStatusText = (status) => {
          const statusMap = {
            0: '待支付',
            1: '開通中',
            2: '已取消',
            3: '已完成',
            4: '已折抵'
          };
          return statusMap[status] || '未知';
        };

        const getOrderStatusClass = (status) => {
          const classMap = {
            0: 'text-yellow-400',
            1: 'text-blue-400',
            2: 'text-gray-400',
            3: 'text-green-400',
            4: 'text-purple-400'
          };
          return classMap[status] || 'text-gray-400';
        };

        const getOrderTypeText = (type) => {
          const typeMap = {
            1: '新購',
            2: '續費',
            3: '升級',
            4: '重置流量包'
          };
          return typeMap[type] || '未知';
        };

        const getPeriodText = (period) => {
          const periodMap = {
            'month_price': '月付',
            'quarter_price': '季付',
            'half_year_price': '半年付',
            'year_price': '年付',
            'two_year_price': '兩年付',
            'three_year_price': '三年付',
            'onetime_price': '一次性',
            'reset_price': '重置流量'
          };
          return periodMap[period] || period;
        };

        const getCommissionStatusText = (status) => {
          const statusMap = {
            0: '待確認',
            1: '發放中',
            2: '已發放',
            3: '已扣回'
          };
          return statusMap[status] || '未知';
        };

        const connectToWebSocket = () => {
          const wsUrl = \`wss://\${window.location.host}\`;
          webSocket.value = new WebSocket(wsUrl);
          connectionStatus.value = "connecting";
          addLog(reconnectAttempts.value > 0 ? \`重連中 (嘗試 \${reconnectAttempts.value})...\` : "正在連線到伺服器...");

          webSocket.value.onopen = () => {
            connectionStatus.value = "connected";
            addLog("連線已建立。", "success");
            reconnectAttempts.value = 0;
            sendWsMessage("refreshAllData"); // Trigger initial fetch of all data
          };

          webSocket.value.onmessage = ({ data }) => {
            try {
              const msg = JSON.parse(data);
              switch (msg.type) {
                case "status": connectionStatus.value = msg.payload; break;
                case "log": addLog(msg.payload.message, msg.payload.type); break;
                case "notification": addNotification(msg.payload.message, msg.payload.type); break;
                case "visitor_info": visitorDetails.value = msg.payload; break;
                case "traffic_update": {
                  const index = trafficData.value.findIndex(d => d.sourceName === msg.payload.sourceName);
                  if (index !== -1) trafficData.value[index] = { ...msg.payload, isLoading: false };
                  else trafficData.value.push({ ...msg.payload, isLoading: false }); // Should not happen with pre-defined list, but for safety
                  break;
                }
                case "balance_update":
                  isRefreshingBalance.value = false;
                  if (msg.payload.error) accountError.value = msg.payload;
                  else accountData.value = msg.payload;
                  break;
                case "v2board_override_update":
                  isRefreshingV2Override.value = false;
                  if (msg.payload.error) v2boardOverrideError.value = msg.payload;
                  else v2boardOverrideData.value = msg.payload;
                  break;
                case "v2board_server_today_rank_update":
                  isRefreshingServerToday.value = false;
                  v2boardServerTodayRank.value = msg.payload;
                  break;
                case "v2board_server_last_rank_update":
                  v2boardServerLastRank.value = msg.payload;
                  break;
                case "v2board_user_today_rank_update":
                  isRefreshingUserToday.value = false;
                  v2boardUserTodayRank.value = msg.payload;
                  break;
                case "v2board_user_last_rank_update":
                  v2boardUserLastRank.value = msg.payload;
                  break;
                case "orders_update":
                  isFetchingOrders.value = false;
                  if (msg.payload.error) ordersError.value = msg.payload;
                  else ordersList.value = { ...msg.payload, orders: msg.payload.data }; // Adjusting for the API response structure
                  break;
                case "single_order_update":
                  isFetchingSingleOrder.value = false;
                  if (msg.payload.error) {
                    singleOrderError.value = msg.payload;
                    singleOrderDetails.value = null;
                  } else {
                    singleOrderError.value = null;
                    // If 'data' key exists and is an array, take the first element. Otherwise, the payload itself is the order data.
                    singleOrderDetails.value = msg.payload.data && Array.isArray(msg.payload.data) ? msg.payload.data[0] : msg.payload;
                    // Ensure singleOrderDetails is null if no valid order data is found (e.g., empty object or no relevant keys)
                    if (!singleOrderDetails.value || (typeof singleOrderDetails.value === 'object' && Object.keys(singleOrderDetails.value).length === 0) || !singleOrderDetails.value.trade_no) {
                      singleOrderError.value = { error: "未找到訂單", details: "沒有找到符合該訂單號的記錄。" };
                      singleOrderDetails.value = null; // Ensure details are null if not found
                    }
                  }
                  isOrderDetailsModalOpen.value = true;
                  break;
                case "v2board_orders_update":
                  isFetchingV2BoardOrders.value = false;
                  if (msg.payload.error) v2boardOrdersError.value = msg.payload;
                  else v2boardOrdersList.value = msg.payload;
                  break;
                case "v2board_order_detail_update":
                  isFetchingV2BoardOrderDetail.value = false;
                  if (msg.payload.error) {
                    v2boardOrderDetailError.value = msg.payload;
                    v2boardOrderDetail.value = null;
                  } else {
                    v2boardOrderDetailError.value = null;
                    v2boardOrderDetail.value = msg.payload.data;
                  }
                  isV2BoardOrderDetailsModalOpen.value = true;
                  break;
                case "v2board_user_info_update":
                  isFetchingUserInfo.value = false;
                  if (msg.payload.error) {
                    userInfoError.value = msg.payload;
                    userInfo.value = null;
                  } else {
                    userInfoError.value = null;
                    userInfo.value = msg.payload.data;
                  }
                  isUserInfoModalOpen.value = true;
                  break;
              }
              
              // Reset refresh states after data updates
              if (msg.type === "status" && msg.payload === "connected") {
                isRefreshingTraffic.value = false;
              }
            } catch(e) {
              console.error("Failed to parse WebSocket message:", e);
              addLog("收到無效的伺服器消息", "error");
            }
          };

          webSocket.value.onclose = () => {
            connectionStatus.value = "disconnected";
            addLog("連線已斷開。", "warn");
            if (reconnectAttempts.value < 5) { // Max 5 reconnect attempts
              reconnectAttempts.value++;
              setTimeout(connectToWebSocket, 3000 * reconnectAttempts.value); // Exponential backoff
            } else {
              addLog("無法重新連線到伺服器。請刷新頁面。", "error");
              addNotification("無法連線到伺服器。請嘗試刷新頁面。", "error", 10000);
            }
          };

          webSocket.value.onerror = (event) => {
            console.error("WebSocket error observed:", event);
            addLog("WebSocket 連線錯誤。", "error");
          };
        };

        const sendWsMessage = (action, payload = {}) => {
          if (webSocket.value?.readyState !== WebSocket.OPEN) {
            addLog("無法發送消息：WebSocket 未開啟。", "error");
            addNotification("無法發送請求：伺服器未連線。", "error");
            return;
          }
          webSocket.value.send(JSON.stringify({ action, ...payload }));
        };

        // Fetch latest N orders
        const fetchBatchOrders = () => {
          isFetchingOrders.value = true;
          ordersError.value = null;
          sendWsMessage("fetchOrders", { page: 1, limit: DEFAULT_ORDERS_PER_PAGE });
        };

        const fetchSingleOrderDetails = () => {
          if (!singleOrderInput.value) return;
          isFetchingSingleOrder.value = true;
          singleOrderError.value = null; // Clear previous error
          singleOrderDetails.value = null; // Clear previous details
          sendWsMessage("fetchSingleOrder", { outTradeNo: singleOrderInput.value });
        };

        const viewOrderDetails = (orderId) => {
          singleOrderInput.value = orderId;
          fetchSingleOrderDetails();
        };

        const fetchV2BoardOrders = () => {
          isFetchingV2BoardOrders.value = true;
          v2boardOrdersError.value = null;
          sendWsMessage("fetchV2BoardOrders", { v2page: 1, v2pageSize: 10 });
        };

        const viewV2BoardOrderDetails = (orderId) => {
          isFetchingV2BoardOrderDetail.value = true;
          v2boardOrderDetailError.value = null;
          v2boardOrderDetail.value = null;
          sendWsMessage("fetchV2BoardOrderDetail", { orderId });
        };

        const viewUserInfo = (userId) => {
          isFetchingUserInfo.value = true;
          userInfoError.value = null;
          userInfo.value = null;
          sendWsMessage("fetchV2BoardUserInfo", { userId });
        };

        // Individual refresh functions for each data card
        const refreshAllTrafficData = () => {
          isRefreshingTraffic.value = true;
          sendWsMessage("refreshAllTrafficData");
        };

        const refreshBalanceData = () => {
          isRefreshingBalance.value = true;
          sendWsMessage("refreshBalance");
        };

        const refreshV2boardOverrideData = () => {
          isRefreshingV2Override.value = true;
          sendWsMessage("refreshV2boardOverride");
        };

        const refreshV2boardServerTodayRank = () => {
          isRefreshingServerToday.value = true;
          sendWsMessage("refreshV2boardServerTodayRank");
        };

        const refreshV2boardUserTodayRank = () => {
          isRefreshingUserToday.value = true;
          sendWsMessage("refreshV2boardUserTodayRank");
        };

        const toggleSettingsModal = () => isSettingsModalOpen.value = !isSettingsModalOpen.value;

        const handleLogout = async () => {
          try {
            const response = await fetch('/api/logout', { method: 'POST' });
            const result = await response.json();
            if (result.success) {
              // Clear any local storage items if needed (e.g., theme preference might be kept)
              // localStorage.removeItem('some_item');
              addNotification("已成功登出。", "success");
              setTimeout(() => {
                window.location.href = '/'; // Redirect to login page
              }, 1000);
            } else {
              addNotification(\`登出失敗: \${result.message}\`, "error");
            }
          } catch (e) {
            addNotification(\`登出請求出錯: \${e.message}\`, "error");
          }
        };

        const toggleTheme = () => {
          isDark.value = !isDark.value;
          localStorage.setItem('theme', isDark.value ? 'dark' : 'light');
          document.documentElement.classList.toggle('dark', isDark.value);
        };

        onMounted(() => connectToWebSocket());
        onUnmounted(() => { if (webSocket.value) webSocket.value.close(); });

        return {
          connectionStatus, statusText, statusPillClass, statusDotClass,
          accountData, accountError, refreshBalanceData, isRefreshingBalance,
          v2boardOverrideData, v2boardOverrideError, refreshV2boardOverrideData, isRefreshingV2Override,
          v2boardServerTodayRank, v2boardServerLastRank, refreshV2boardServerTodayRank, isRefreshingServerToday,
          v2boardUserTodayRank, v2boardUserLastRank, refreshV2boardUserTodayRank, isRefreshingUserToday,
          ordersList, ordersError, isFetchingOrders, fetchBatchOrders,
          singleOrderInput, singleOrderDetails, singleOrderError, isFetchingSingleOrder, fetchSingleOrderDetails, viewOrderDetails, isOrderDetailsModalOpen,
          trafficData,
          systemLogs, notifications, getNotificationIcon,
          visitorDetails,
          isSettingsModalOpen, toggleSettingsModal,
          isDark, toggleTheme,
          handleLogout, // Expose logout function
          formatTraffic, formatTimestamp,
          DEFAULT_ORDERS_PER_PAGE, // Expose to template
          refreshAllTrafficData, isRefreshingTraffic,
          // V2Board orders
          v2boardOrdersList, v2boardOrdersError, isFetchingV2BoardOrders, fetchV2BoardOrders,
          v2boardOrderDetail, v2boardOrderDetailError, isFetchingV2BoardOrderDetail, viewV2BoardOrderDetails, isV2BoardOrderDetailsModalOpen,
          // User info
          userInfo, userInfoError, isFetchingUserInfo, viewUserInfo, isUserInfoModalOpen,
          // Helper functions
          getOrderStatusText, getOrderStatusClass, getOrderTypeText, getPeriodText, getCommissionStatusText,
        };
      },
    }).mount("#app");
  </script>
</body>
</html>`;
}
