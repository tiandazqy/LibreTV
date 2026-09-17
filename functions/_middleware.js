// LibreTV Cloudflare Pages 边缘鉴权
import { sha256 } from 'crypto';

export async function onRequest(context) {
    const { request, env } = context;
    const PASSWORD = env.PASSWORD;
    if (!PASSWORD) {
        return new Response(`<html><body><h2>请先在部署平台设置PASSWORD环境变量</h2></body></html>`, {status:403});
    }
    const cookie = request.headers.get('cookie') || '';
    const cookieMatch = cookie.match(/libretv_auth=([0-9a-f]+)/);
    if (cookieMatch) {
        const hash = cookieMatch[1];
        const expected = await sha256(PASSWORD);
        if (hash === expected) {
            return await context.next();
        }
    }
    if (request.method === 'POST') {
        const formData = await request.formData();
        const inputPwd = formData.get('password');
        if (inputPwd === PASSWORD) {
            const hash = await sha256(PASSWORD);
            const headers = new Headers();
            headers.append('Set-Cookie',`libretv_auth=${hash}; Path=/; Max-Age=2592000; SameSite=Lax`);
            return new Response(null, {status:302, headers,});
        }
    }
    const html = `
    <html>
    <head><title>LibreTV 访问验证</title></head>
    <body style="display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#111;color:#fff;">
        <form method="POST">
            <h2>输入访问密码</h2>
            <input type="password" name="password" autofocus style="padding:8px;font-size:18px;"><br/><br/>
            <button type="submit" style="padding:8px 16px;font-size:18px;">提交</button>
        </form>
    </body>
    </html>`;
    return new Response(html, {headers:{"content-type":"text/html"}});
}
