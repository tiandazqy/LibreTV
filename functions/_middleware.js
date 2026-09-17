// functions/_middleware.js
export async function onRequest({ request, env, next }) {
  const PASSWORD = env.PASSWORD;
  if (!PASSWORD) {
    return new Response("未配置环境变量 PASSWORD", { status: 500 });
  }

  const cookieName = "libretv_auth";
  const cookie = request.headers.get("cookie") || "";
  const cookieMatch = cookie.match(new RegExp(`${cookieName}=([^;]+)`));

  // 校验cookie
  if (cookieMatch) {
    const token = cookieMatch[1];
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(PASSWORD));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const expectedHash = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
    if (token === expectedHash) {
      return next();
    }
  }

  // POST提交密码
  if (request.method === "POST") {
    const formData = await request.formData();
    const inputPwd = formData.get("password") || "";
    if (inputPwd === PASSWORD) {
      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(PASSWORD));
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hash = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
      const headers = new Headers();
      headers.append("Set-Cookie", `${cookieName}=${hash}; Path=/; Max-Age=2592000; SameSite=Lax`);
      headers.append("Location", "/");
      return new Response(null, { status: 302, headers });
    } else {
      return renderPage("密码错误，请重试");
    }
  }

  return renderPage();
}

function renderPage(msg = "") {
  const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>访问验证</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#111;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh}
.box{background:#222;padding:32px;border-radius:12px;width:340px}
h2{margin-bottom:20px;text-align:center}
form{display:flex;gap:10px}
input{flex:1;padding:12px;border:none;border-radius:6px;font-size:16px}
button{padding:12px 18px;background:#2563eb;color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:bold}
.tip{color:#f87171;margin-top:12px;text-align:center}
</style>
</head>
<body>
<div class="box">
<h2>网站访问验证</h2>
<form method="POST">
<input type="password" name="password" placeholder="输入访问密码" required>
<button type="submit">提交</button>
</form>
${msg ? `<div class="tip">${msg}</div>` : ""}
</div>
</body>
</html>`;
  return new Response(html, { headers: { "content-type": "text/html;charset=utf-8" } });
}
