"""
CordCloud Auto Login + Daily Check-in
使用 CloakBrowser (Playwright兼容) + POP3 邮箱验证码
"""

import os
import sys
import re
import time
import poplib
import smtplib
import email

# Windows 中文环境终端默认 GBK，无法输出 emoji，强制 UTF-8
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from email.header import decode_header
from email.utils import parsedate_to_datetime, formatdate
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from dotenv import load_dotenv

# CloakBrowser 提供 Playwright 兼容 API
from cloakbrowser import launch, launch_persistent_context

# ── 配置 ────────────────────────────────────────────
_env_loaded = load_dotenv()
if not _env_loaded:
    print("[Config] 未找到 .env 文件，使用系统环境变量")

def _env(key: str, default: str = "") -> str:
    """读取环境变量，空字符串视为未设置，返回默认值"""
    val = os.getenv(key)
    return val if val else default

def _mask_code(code: str) -> str:
    """脱敏验证码，仅保留首尾字符"""
    if len(code) <= 2:
        return "*" * len(code)
    return code[0] + "*" * (len(code) - 2) + code[-1]

CORDCLOUD_EMAIL = _env("CORDCLOUD_EMAIL")
CORDCLOUD_PASSWORD = _env("CORDCLOUD_PASSWORD")

# POP3 配置
POP3_HOST = _env("POP3_HOST", "pop.example.com")
POP3_PORT = int(_env("POP3_PORT", "995"))
POP3_USE_SSL = _env("POP3_USE_SSL", "true").lower() == "true"
POP3_USERNAME = _env("POP3_USERNAME", CORDCLOUD_EMAIL)
POP3_PASSWORD = _env("POP3_PASSWORD")

# SMTP 配置（发送签到结果通知）
SMTP_HOST = _env("SMTP_HOST", "smtp.qq.com")
SMTP_PORT = int(_env("SMTP_PORT", "465"))
SMTP_USE_SSL = _env("SMTP_USE_SSL", "true").lower() == "true"
SMTP_USERNAME = _env("SMTP_USERNAME", CORDCLOUD_EMAIL)
SMTP_PASSWORD = _env("SMTP_PASSWORD")

# 持久化配置
USE_PERSISTENT = _env("USE_PERSISTENT_CONTEXT", "true").lower() == "true"
PROFILE_DIR = Path(_env("PERSISTENT_PROFILE_DIR", "./cloak_profile"))
HEADLESS = _env("HEADLESS", "false").lower() == "true"

LOGIN_URL = "https://www.cordcloud.one/auth/login"
USER_URL = "https://www.cordcloud.one/user"

# 调试：保存每步 HTML
DEBUG_HTML_DIR = Path("./debug_html")
SAVE_HTML = _env("SAVE_HTML", "true").lower() == "true"

# ── 调试工具 ─────────────────────────────────────

def save_page_state(page, step_name: str) -> str | None:
    """保存当前页面的 HTML 和截图，用于分析页面结构。返回截图路径。"""
    if not SAVE_HTML:
        return None
    DEBUG_HTML_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%H%M%S")
    html_path = DEBUG_HTML_DIR / f"{timestamp}_{step_name}.html"
    png_path = DEBUG_HTML_DIR / f"{timestamp}_{step_name}.png"
    try:
        html_path.write_text(page.content(), encoding="utf-8")
        print(f"[DEBUG] HTML 已保存: {html_path}")
    except Exception as e:
        print(f"[DEBUG] HTML 保存失败: {e}")
    try:
        page.screenshot(path=str(png_path), full_page=False)
        print(f"[DEBUG] 截图已保存: {png_path}")
        return str(png_path)
    except Exception as e:
        print(f"[DEBUG] 截图保存失败: {e}")
        return None


# ── SMTP 发送工具 ─────────────────────────────────────

def send_result_email(subject: str, body: str, image_path: str | None = None):
    """通过 SMTP 发送签到结果邮件（自己发给自己），可选附带截图"""
    if not SMTP_PASSWORD:
        print("[SMTP] 未配置 SMTP_PASSWORD，跳过邮件发送")
        return

    try:
        if image_path:
            msg = MIMEMultipart("related")
            msg["From"] = SMTP_USERNAME
            msg["To"] = CORDCLOUD_EMAIL
            msg["Subject"] = subject
            msg["Date"] = formatdate(localtime=True)

            # 文本部分
            text_part = MIMEText(body, "plain", "utf-8")
            msg.attach(text_part)

            # 图片附件
            with open(image_path, "rb") as f:
                img = MIMEImage(f.read(), _subtype="png")
                img.add_header("Content-Disposition", "attachment", filename=Path(image_path).name)
                msg.attach(img)
        else:
            msg = MIMEText(body, "plain", "utf-8")
            msg["From"] = SMTP_USERNAME
            msg["To"] = CORDCLOUD_EMAIL
            msg["Subject"] = subject
            msg["Date"] = formatdate(localtime=True)

        if SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
            server.starttls()

        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, [CORDCLOUD_EMAIL], msg.as_string())
        server.quit()
        print(f"[SMTP] ✅ 结果邮件已发送至 {CORDCLOUD_EMAIL}")
    except Exception as e:
        print(f"[SMTP] ❌ 邮件发送失败: {e}")


# ── POP3 邮箱工具 ─────────────────────────────────────

def decode_mime_header(header_value):
    """解码 MIME 编码的邮件头"""
    if header_value is None:
        return ""
    parts = decode_header(header_value)
    result = []
    for part, charset in parts:
        if isinstance(part, bytes):
            result.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            result.append(str(part))
    return "".join(result)


def fetch_latest_verification_code(timeout_seconds=60, poll_interval=3, since_time=None):
    """
    通过 POP3 收取最新邮件中的验证码。
    since_time: Unix 时间戳，只接受该时间之后的邮件（防止读取历史验证码）
    返回 (code: str | None, error: str | None)

    注意：Gmail POP3 的邮件顺序不保证验证码在最后一封（可能被分类/延迟），
    因此扫描最近 SCAN_COUNT 封邮件（从最新往回），而非只看最后一封。
    """
    SCAN_COUNT = 10  # 每次扫描最近的邮件数
    deadline = time.time() + timeout_seconds
    scanned_upto = 0  # 已扫描过的最小邮件序号（避免重复解析）

    while time.time() < deadline:
        try:
            if POP3_USE_SSL:
                conn = poplib.POP3_SSL(POP3_HOST, POP3_PORT, timeout=10)
            else:
                conn = poplib.POP3(POP3_HOST, POP3_PORT, timeout=10)

            conn.user(POP3_USERNAME)
            conn.pass_(POP3_PASSWORD)

            msg_count, _ = conn.stat()
            print(f"[POP3] 邮箱共 {msg_count} 封邮件")

            if msg_count == 0:
                conn.quit()
                time.sleep(poll_interval)
                continue

            # 扫描范围：从最新一封往回，跳过已扫描过的
            start = msg_count
            end = max(scanned_upto + 1, msg_count - SCAN_COUNT + 1)
            if start < end:
                conn.quit()
                time.sleep(poll_interval)
                continue

            code_found = None
            for idx in range(start, end - 1, -1):
                resp, lines, octets = conn.retr(idx)
                raw_email = b"\r\n".join(lines)

                msg = email.message_from_bytes(raw_email)
                subject = decode_mime_header(msg["Subject"] or "")
                sender = decode_mime_header(msg["From"] or "")
                date = msg.get("Date", "")

                print(f"[POP3] 第{idx}封: 发件人={sender}, 主题={subject}, 时间={date}")

                # 时间过滤：跳过登录触发前收到的邮件，防止读取历史验证码
                if since_time is not None and date:
                    try:
                        email_dt = parsedate_to_datetime(date)
                        # 容忍 5 分钟时钟偏差
                        if email_dt.timestamp() < since_time - 300:
                            continue
                    except Exception:
                        pass  # 日期解析失败不阻塞

                # 提取正文（优先纯文本，避免 HTML 噪声干扰）
                text_parts = []
                html_parts = []
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        if content_type not in ("text/plain", "text/html"):
                            continue
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            decoded = payload.decode(charset, errors="replace")
                            if content_type == "text/plain":
                                text_parts.append(decoded)
                            else:
                                html_parts.append(decoded)
                else:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        charset = msg.get_content_charset() or "utf-8"
                        text_parts.append(payload.decode(charset, errors="replace"))

                # 纯文本优先（噪声少），再拼接 HTML
                plain_body = "\n".join(text_parts)
                full_body = plain_body + "\n" + "\n".join(html_parts)

                # 从正文中提取验证码
                # 策略：优先匹配数字验证码（站点要求6位数字），字母数字作为兜底
                digit_patterns = [
                    # 紧邻 "验证码" 的 6 位数字（最精确）
                    (r"验证码[：:\s]*(?:是|为)?[：:\s]*(\d{6})", "6位数字紧邻验证码"),
                    # "code:" 后 6 位数字
                    (r"(?:code|Code|CODE)[：:\s]*(\d{6})", "6位数字紧邻code"),
                    # 正文中任意 6 位数字（大概率是验证码）
                    (r"(?<!\d)(\d{6})(?!\d)", "独立6位数字"),
                ]
                alphanum_patterns = [
                    # "验证码" 后 4-8 位字母数字（兜底）
                    (r"验证码[：:\s]*(?:是|为)?[：:\s]*([A-Za-z0-9]{4,8})", "4-8位字母数字紧邻验证码"),
                    # "code:" 后 4-8 位字母数字
                    (r"(?:code|Code|CODE)[：:\s]*([A-Za-z0-9]{4,8})", "4-8位字母数字紧邻code"),
                ]

                def try_extract(body: str, label: str) -> str | None:
                    """在给定文本中尝试提取验证码，优先数字模式"""
                    for pattern, desc in digit_patterns + alphanum_patterns:
                        match = re.search(pattern, body)
                        if match:
                            code = match.group(1)
                            # 打印匹配上下文便于调试
                            start_c = max(0, match.start() - 20)
                            end_c = min(len(body), match.end() + 20)
                            ctx = body[start_c:end_c].replace("\n", " ")
                            print(f"[POP3] ✅ [{label}] {desc}: {_mask_code(code)} (上下文: ...{ctx}...)")
                            return code
                    return None

                # 先搜纯文本，再搜全文
                code = try_extract(plain_body, "纯文本")
                if code is None:
                    code = try_extract(full_body, "全文")
                if code is not None:
                    code_found = code
                    break

                # 降级：打印正文前 200 字符供人工判断（仅新邮件）
                if idx == start:
                    print(f"[POP3] ⚠️ 最新邮件未提取到验证码，纯文本前200字符:")
                    print(plain_body[:200])

            scanned_upto = start  # 记录本轮已扫描到的最新位置

            if code_found is not None:
                conn.quit()
                return code_found, None

            conn.quit()

        except Exception as e:
            print(f"[POP3] 连接错误: {e}")
            time.sleep(poll_interval)
            continue

        time.sleep(poll_interval)

    return None, f"超时 {timeout_seconds}s 未获取到验证码"


# ── CloakBrowser 主流程 ─────────────────────────────

def main():
    print("=" * 60)
    print("CordCloud Auto Login + Daily Check-in")
    print(f"CloakBrowser + POP3 ({POP3_HOST}:{POP3_PORT})")
    print("=" * 60)

    # 校验配置
    if not CORDCLOUD_EMAIL or not CORDCLOUD_PASSWORD:
        print("[ERROR] 请先配置 .env 文件中的 CORDCLOUD_EMAIL 和 CORDCLOUD_PASSWORD")
        return

    # 启动 CloakBrowser（Playwright 兼容）
    print("\n[Browser] 启动 CloakBrowser...")
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)

    if USE_PERSISTENT:
        context = launch_persistent_context(
            PROFILE_DIR,
            headless=HEADLESS,
            viewport={"width": 1280, "height": 800},
            humanize=True,
        )
        # launch_persistent_context returns BrowserContext (Playwright-compatible)
        page = context.new_page()
        real_browser = None  # persistent context manages its own browser
    else:
        real_browser = launch(headless=HEADLESS, humanize=True)
        context = real_browser.new_context(viewport={"width": 1280, "height": 800})
        page = context.new_page()

    results = []  # 收集各步骤结果用于邮件汇总
    checkin_screenshot = None  # 签到页面截图路径

    try:
        # ── Step 1: 检查是否已登录 ──
        print("\n[Step 1] 检查登录状态...")
        page.goto(USER_URL, wait_until="networkidle", timeout=30000)
        page.wait_for_timeout(1000)
        save_page_state(page, "step1_check_login")

        # 如果跳转到 /user 则已登录
        current_url = page.url
        if "/user" in current_url or "/user/" in current_url:
            print("[Step 1] ✅ 已有有效会话，跳过登录")
            results.append("[Step 1] 已有有效会话，跳过登录")
        else:
            # ── Step 2: 登录 ──
            print("\n[Step 2] 开始登录...")
            page.goto(LOGIN_URL, wait_until="networkidle", timeout=30000)

            # 等待 ALtcha 验证码自动验证完成（auto="onload"）
            print("[Step 2] 等待 ALtcha 验证码...")
            try:
                page.wait_for_function(
                    """() => {
                        const altcha = document.querySelector('.altcha');
                        return altcha && altcha.getAttribute('data-state') === 'verified';
                    }""",
                    timeout=30000
                )
                print("[Step 2] ✅ ALtcha 验证完成")
            except Exception:
                print("[Step 2] ⚠️ ALtcha 等待超时，尝试继续...")

            save_page_state(page, "step2_login_page")

            # 等待表单就绪，避免页面 JS 尚未初始化完成导致 fill 竞态
            email_input = page.locator("#email")
            passwd_input = page.locator("#passwd")
            email_input.wait_for(state="visible", timeout=10000)
            passwd_input.wait_for(state="visible", timeout=10000)

            # 注意：此站点存在反自动化处理，locator.fill() 填入的值会在
            # 下一次填充动作时被清空（先填的框保留、后填的被清）。必须用
            # JS 一次性设值 + 派发 input/change 事件，两个框才能同时有值。
            page.evaluate(
                """([emailVal, passVal]) => {
                    const setVal = (id, v) => {
                        const el = document.getElementById(id);
                        el.focus();
                        el.value = v;
                        el.dispatchEvent(new Event('input', {bubbles: true}));
                        el.dispatchEvent(new Event('change', {bubbles: true}));
                    };
                    setVal('email', emailVal);
                    setVal('passwd', passVal);
                    document.activeElement.blur();
                }""",
                [CORDCLOUD_EMAIL, CORDCLOUD_PASSWORD],
            )
            page.wait_for_timeout(500)

            # 验证填入的值是否正确（防止设值失败）
            filled_email = email_input.input_value()
            filled_passwd = passwd_input.input_value()
            if not filled_email or not filled_passwd:
                print(f"[Step 2] ⚠️ 设值异常 (email={filled_email!r}, passwd={'有值' if filled_passwd else '空'})，JS 重试...")
                page.evaluate(
                    """([emailVal, passVal]) => {
                        const setVal = (id, v) => {
                            const el = document.getElementById(id);
                            el.value = v;
                            el.dispatchEvent(new Event('input', {bubbles: true}));
                            el.dispatchEvent(new Event('change', {bubbles: true}));
                        };
                        setVal('email', emailVal);
                        setVal('passwd', passVal);
                    }""",
                    [CORDCLOUD_EMAIL, CORDCLOUD_PASSWORD],
                )
                filled_email = email_input.input_value()
                filled_passwd = passwd_input.input_value()
                if not filled_email or not filled_passwd:
                    print(f"[Step 2] ❌ 重试仍失败: email={filled_email!r}, passwd={'有值' if filled_passwd else '空'}")
                else:
                    print(f"[Step 2] ✅ 重试成功")

            print(f"[Step 2] 已填写: {CORDCLOUD_EMAIL}")
            results.append(f"[Step 2] 填写登录表单: {CORDCLOUD_EMAIL}")

            # 点击登录按钮（触发 AJAX login() 函数）
            # AJAX 返回：
            #   ret==1 → 弹窗 → 500ms后 location.href='/user'
            #   ret==2 → 弹窗 → 500ms后 location.href='/auth/login/2fa?token=...'
            #   其他   → 弹窗显示错误，留在当前页
            login_click_time = time.time()
            page.click("#login")
            print(f"[Step 2] 已点击登录 (触发时间: {time.strftime('%H:%M:%S', time.localtime(login_click_time))})，等待 AJAX 响应...")

            # 等待 JS 重定向：优先检测跳转到 /user（登录成功），其次 /2fa（需要二步验证）
            redirected = False
            for label, pattern, timeout_s in [
                ("登录成功→/user", "**/user**", 15),
                ("二步验证→/2fa", "**/2fa**", 10),
            ]:
                try:
                    page.wait_for_url(pattern, timeout=timeout_s * 1000)
                    print(f"[Step 2] ✅ 检测到跳转: {label}")
                    redirected = True
                    break
                except Exception:
                    continue

            # 兜底：短暂等待后再次检查 URL（某些情况下 wait_for_url 可能错过）
            if not redirected:
                page.wait_for_timeout(2000)
                if "/user" in page.url or "/2fa" in page.url:
                    redirected = True

            current_url = page.url
            print(f"[Step 2] 当前 URL: {current_url}")
            save_page_state(page, "step3_after_login_click")

            # ── 检测 2FA ──
            in_2fa = ("/2fa" in current_url or "/auth/login/2fa" in current_url)

            if in_2fa:
                print(f"[Step 2] 🔐 检测到 2FA 页面")
                save_page_state(page, "step3_2fa_page")
                print("[Step 2] 正在从 POP3 收取验证码...")

                # 首轮收取（45s）。失败则点击"重新发送"再收一轮（60s），
                # 应对首封验证码邮件丢失/延迟的情况。
                code, error = fetch_latest_verification_code(timeout_seconds=45, since_time=login_click_time)
                if not code:
                    print("[Step 2] ⏳ 首轮未收到验证码，尝试点击'重新发送'...")
                    try:
                        resend_btn = page.locator("#resend-code")
                        if resend_btn.is_visible():
                            resend_click_time = time.time()
                            resend_btn.click()
                            print(f"[Step 2] 已点击重新发送 (触发时间: {time.strftime('%H:%M:%S', time.localtime(resend_click_time))})")
                            code, error = fetch_latest_verification_code(
                                timeout_seconds=60, since_time=resend_click_time
                            )
                    except Exception as e:
                        print(f"[Step 2] ⚠️ 点击重新发送失败: {e}")

                if error or not code:
                    print(f"[Step 2] ❌ {error}")
                    return

                # 填写验证码：尝试多种选择器（页面结构可能变化）
                code_filled = False
                for selector in ["#code", "input[name='code']", "input[type='text']"]:
                    try:
                        code_input = page.locator(selector).first
                        if code_input.is_visible():
                            code_input.fill(code, force=True)
                            code_filled = True
                            print(f"[Step 2] 已填写验证码 (selector={selector}): {_mask_code(code)}")
                            break
                    except Exception:
                        continue
                if not code_filled:
                    print(f"[Step 2] ⚠️ 未找到验证码输入框，尝试继续...")

                # 提交 2FA：尝试多种选择器
                verify_clicked = False
                for selector in ["#btn-verify", "button:has-text('验证')", "button:has-text('确认')", "button[type='submit']"]:
                    try:
                        verify_btn = page.locator(selector).first
                        if verify_btn.is_visible():
                            verify_btn.click()
                            verify_clicked = True
                            print(f"[Step 2] 已点击验证按钮 (selector={selector})")
                            break
                    except Exception:
                        continue
                if not verify_clicked:
                    print("[Step 2] ⚠️ 未找到验证按钮，尝试继续...")

                print("[Step 2] 已提交验证，等待响应...")

                # 等待结果：成功则跳转到 /user，失败则弹窗 #msg
                try:
                    page.wait_for_url("**/user**", timeout=10000)
                    print("[Step 2] ✅ 2FA 验证成功，已跳转到用户页面")
                    results.append("[Step 2] 2FA 验证成功")
                except Exception:
                    # 未跳转，检查 #msg 弹窗错误信息
                    try:
                        msg_el = page.locator("#msg")
                        if msg_el.is_visible():
                            error_text = (msg_el.text_content() or "").strip()
                            print(f"[Step 2] ❌ 2FA 验证失败: {error_text}")
                            results.append(f"[Step 2] 2FA 验证失败: {error_text}")
                            return
                    except Exception:
                        pass
                    print("[Step 2] ⚠️ 2FA 提交后未跳转，状态未知")

                save_page_state(page, "step4_after_2fa")
            else:
                # 不在 2FA 页面 → 检查是否有错误弹窗（登录失败）
                try:
                    page.wait_for_timeout(1000)
                    msg_el = page.locator("#msg")
                    if msg_el.is_visible():
                        error_msg = (msg_el.text_content() or "").strip()
                        if error_msg:
                            print(f"[Step 2] ❌ 登录错误: {error_msg}")
                            results.append(f"[Step 2] 登录错误: {error_msg}")
                            return
                except Exception:
                    pass

                # 也不在 /user → 可能登录异常
                print(f"[Step 2] ⚠️ 登录后未跳转，当前: {current_url}")
                results.append(f"[Step 2] 登录后未跳转到 /user，当前: {current_url}")

            current_url = page.url

            if "/user" in current_url or "/user/" in current_url:
                print("[Step 2] ✅ 登录成功！")
                results.append("[Step 2] 登录成功")
            elif "/2fa" not in current_url:
                print(f"[Step 2] ⚠️ 登录后 URL: {current_url}，继续尝试...")
                results.append(f"[Step 2] 登录后未跳转到 /user，当前: {current_url}")

        # ── Step 3: 每日签到 ──
        print("\n[Step 3] 查找每日签到...")
        page.goto(USER_URL, wait_until="networkidle", timeout=30000)
        page.wait_for_timeout(2000)  # 多等一会让用户页面 JS 初始化
        save_page_state(page, "step5_user_checkin")

        # 签到按钮：尝试多种选择器（页面结构可能变化）
        checkin_selectors = [
            "#checkin-btn button",       # 旧结构：容器内按钮
            "#checkin",                  # 直接 ID
            "button:has-text('签到')",    # 文字匹配
            "button:has-text('每日签到')", # 备选文字
        ]
        checkin_btn = None
        for selector in checkin_selectors:
            try:
                btn = page.locator(selector).first
                if btn.is_visible():
                    # 过滤掉不相关的按钮（如页面导航中的）
                    btn_text = (btn.text_content() or "").strip()
                    if any(kw in btn_text for kw in ("签到", "checkin", "Checkin")):
                        checkin_btn = btn
                        print(f"[Step 3] 找到签到按钮 (selector={selector}): '{btn_text}'")
                        break
            except Exception:
                continue

        if checkin_btn is None:
            print("[Step 3] ⚠️ 未找到签到按钮，页面结构可能有变")
            results.append("[Step 3] 未找到签到按钮")
        else:
            is_disabled = checkin_btn.is_disabled()
            btn_text = (checkin_btn.text_content() or "").strip()
            if is_disabled or "已签到" in btn_text:
                # 提取上次签到时间
                last_time_text = ""
                for last_sel in ["p:has-text('上次')", "span:has-text('上次')", "*:has-text('上次')"]:
                    try:
                        last_el = page.locator(last_sel).first
                        if last_el.is_visible():
                            last_time_text = (last_el.text_content() or "").strip()
                            if last_time_text:
                                break
                    except Exception:
                        continue
                if last_time_text:
                    print(f"[Step 3] 今日已签到，{last_time_text}")
                    results.append(f"[Step 3] 今日已签到，{last_time_text}")
                else:
                    print(f"[Step 3] 今日已签到")
                    results.append("[Step 3] 今日已签到")
            else:
                print(f"[Step 3] 点击签到按钮: '{btn_text}'")
                checkin_btn.click()
                page.wait_for_timeout(2000)

                # 检查签到结果：尝试多种选择器
                checkin_msg = ""
                for msg_sel in ["#checkin-msg", ".checkin-msg", ".alert", "#msg"]:
                    try:
                        msg_el = page.locator(msg_sel).first
                        if msg_el.is_visible():
                            txt = (msg_el.text_content() or "").strip()
                            if txt and len(txt) < 200:  # 合理长度的消息
                                checkin_msg = txt
                                print(f"[Step 3] 签到结果 ({msg_sel}): {checkin_msg}")
                                break
                    except Exception:
                        continue
                if not checkin_msg:
                    # 检查按钮文字是否变化（已签到）
                    try:
                        new_text = (checkin_btn.text_content() or "").strip()
                        if new_text != btn_text:
                            checkin_msg = f"按钮文字变化: {new_text}"
                            print(f"[Step 3] {checkin_msg}")
                    except Exception:
                        pass
                results.append(f"[Step 3] 签到完成: {checkin_msg or '已执行'}")

        print("[Step 3] ✅ 签到操作完成")
        checkin_screenshot = save_page_state(page, "step6_after_checkin")

        # ── 发送结果邮件 ──
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        email_subject = f"CordCloud 签到结果 - {now}"
        email_body = "\n".join(results)
        send_result_email(email_subject, email_body, checkin_screenshot)

        print("\n" + "=" * 60)
        print("✅ 任务完成")
        print("=" * 60)

    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        results.append(f"[ERROR] {e}")

    finally:
        print("\n[Browser] 保持浏览器打开（5秒后自动关闭）...")
        time.sleep(5)
        if USE_PERSISTENT:
            context.close()
        else:
            if real_browser:
                real_browser.close()


if __name__ == "__main__":
    main()
