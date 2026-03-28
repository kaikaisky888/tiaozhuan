#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KVI 域名管理工具
================
支持功能：
1. 批量在 Namesilo 创建子域名 + CNAME 解析
2. 批量在 He.net (Hurricane Electric) 创建子域名 + CNAME 解析
3. 自动更新 domains.json 域名库
4. 检测域名可用性
5. 一键换一批新域名

用法：
  python manage_domains.py --help
  python manage_domains.py check                          # 检测所有域名
    python manage_domains.py add --provider desec --domain a-hui-od.top --subs "app" --target kiv.up.railway.app
  python manage_domains.py add --provider namesilo --domain example.com --subs "app,www,m,h5" --target kiv.up.railway.app
  python manage_domains.py remove --urls "https://app.example.com,https://www.example.com"
    python manage_domains.py rotate --provider desec --domain a-hui-od.top --target kiv.up.railway.app --count 1
"""

import argparse
import json
import os
import sys
import time
import random
import string
import copy
import urllib.request
import urllib.parse
import urllib.error
import ssl
import base64
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import xml.etree.ElementTree as ET

# ========== 配置 ==========
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOMAINS_FILE = os.path.join(BASE_DIR, 'domains.json')
ADMIN_FILE = os.path.join(BASE_DIR, 'admin.html')

DEFAULT_CONFIG = {
    "version": 1,
    "updated": "",
    "siteName": "独立跳转站",
    "servers": {},
    "wildcard": {
        "enabled": True,
        "baseDomain": "a.hui-od.top",
        "candidateCount": 6,
        "labelLength": 8,
    },
    "probeAssets": [
        "/static/index/img/down_left.png",
        "/static/mobile/imgn/coinwin_ico.png",
        "/static/mobile/imgn/recharg_2x.png",
    ],
    "probeAssetThreshold": 2,
    "domains": [],
}

# Namesilo API Key（在 namesilo.com -> API Manager 获取）
NAMESILO_API_KEY = os.environ.get('NAMESILO_API_KEY', '')

# He.net API Key（在 dns.he.net 获取）
HENET_API_KEY = os.environ.get('HENET_API_KEY', '')

# deSEC API Token（在 desec.io 获取）
DESEC_TOKEN = os.environ.get('DESEC_TOKEN', '')

# 后台鉴权（Railway 部署时建议设置）
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASS', '')


def default_config():
    return copy.deepcopy(DEFAULT_CONFIG)


def normalize_config(data):
    config = default_config()
    source = data if isinstance(data, dict) else {}

    config['version'] = int(source.get('version', config['version']) or config['version'])
    config['updated'] = source.get('updated', config['updated'])
    config['siteName'] = source.get('siteName') or config['siteName']
    config['servers'] = source.get('servers', config['servers']) or {}

    wildcard = source.get('wildcard', {}) or {}
    config['wildcard']['enabled'] = bool(wildcard.get('enabled', config['wildcard']['enabled']))
    config['wildcard']['baseDomain'] = wildcard.get('baseDomain') or config['wildcard']['baseDomain']
    config['wildcard']['candidateCount'] = int(wildcard.get('candidateCount', config['wildcard']['candidateCount']) or config['wildcard']['candidateCount'])
    config['wildcard']['labelLength'] = int(wildcard.get('labelLength', config['wildcard']['labelLength']) or config['wildcard']['labelLength'])

    probe_assets = source.get('probeAssets', config['probeAssets']) or []
    config['probeAssets'] = [str(item).strip() for item in probe_assets if str(item).strip()]
    config['probeAssetThreshold'] = int(source.get('probeAssetThreshold', config['probeAssetThreshold']) or config['probeAssetThreshold'])
    config['domains'] = source.get('domains', config['domains']) or []
    return config

# ========== 域名库操作 ==========
def load_domains():
    """加载域名库"""
    if os.path.exists(DOMAINS_FILE):
        with open(DOMAINS_FILE, 'r', encoding='utf-8') as f:
            return normalize_config(json.load(f))
    return default_config()

def save_domains(data):
    """保存域名库"""
    data = normalize_config(data)
    data['updated'] = time.strftime('%Y-%m-%d %H:%M:%S')
    data['version'] = data.get('version', 0) + 1
    with open(DOMAINS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[OK] 域名库已更新: {DOMAINS_FILE}")

def add_to_domains(url, name, provider):
    """添加域名到库"""
    data = load_domains()
    # 检查是否已存在
    for d in data['domains']:
        if d['url'] == url:
            print(f"[跳过] 已存在: {url}")
            return
    data['domains'].append({"url": url, "name": name, "provider": provider})
    save_domains(data)
    print(f"[添加] {name} -> {url}")

def remove_from_domains(urls):
    """从域名库移除"""
    data = load_domains()
    before = len(data['domains'])
    data['domains'] = [d for d in data['domains'] if d['url'] not in urls]
    after = len(data['domains'])
    save_domains(data)
    print(f"[移除] 删除了 {before - after} 条域名")

# ========== 网络请求工具 ==========
def make_http_request(url, method='GET', data=None, headers=None, timeout=30):
    """统一封装 HTTP 请求"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('User-Agent', 'KVI-Domain-Manager/1.0')
    if headers:
        for k, v in headers.items():
            if k.lower() == 'user-agent':
                try:
                    req.remove_header('User-agent')
                except Exception:
                    pass
            req.add_header(k, v)
            
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)

# ========== 域名检测 ==========
def check_domain(url, probe_assets, threshold, timeout=8):
    """检测域名是否可访问（资源探测，与前端逻辑一致）"""
    base_url = url.rstrip('/')
    start = time.time()
    ok_count = 0

    for path in probe_assets:
        asset_url = base_url + path + '?t=' + str(int(time.time()))
        try:
            resp = make_http_request(asset_url, method='GET', headers={'User-Agent': 'Mozilla/5.0'}, timeout=timeout)
            if resp.status == 200:
                ok_count += 1
            if ok_count >= threshold:
                break
        except Exception:
            continue

    latency = int((time.time() - start) * 1000)
    if ok_count >= threshold:
        return True, latency, f'{ok_count}/{len(probe_assets)} assets OK'
    return False, 0, f'{ok_count}/{len(probe_assets)} assets (need {threshold})'

def check_all():
    """检测所有域名"""
    data = load_domains()
    if not data['domains']:
        print("域名库为空")
        return

    probe_assets = data.get('probeAssets', DEFAULT_CONFIG['probeAssets'])
    threshold = int(data.get('probeAssetThreshold', DEFAULT_CONFIG['probeAssetThreshold']))

    print(f"\n{'='*60}")
    print(f"  KVI 域名检测  ({len(data['domains'])} 条线路)")
    print(f"  探测模式: 资源命中 {threshold}/{len(probe_assets)}")
    print(f"{'='*60}\n")

    ok_count = 0
    for d in data['domains']:
        ok, latency, status = check_domain(d['url'], probe_assets, threshold)
        if ok:
            ok_count += 1
            print(f"  ✅ {d['name']:10s}  {d['url']:40s}  {latency}ms")
        else:
            print(f"  ❌ {d['name']:10s}  {d['url']:40s}  失败: {status}")

    print(f"\n{'='*60}")
    print(f"  结果: {ok_count}/{len(data['domains'])} 可用")
    print(f"{'='*60}\n")

# ========== Namesilo API ==========
def namesilo_api(command, params=None):
    """调用 Namesilo API"""
    if not NAMESILO_API_KEY:
        print("[错误] 未设置 NAMESILO_API_KEY 环境变量")
        print("  获取方法: namesilo.com -> Account -> API Manager -> Generate")
        print("  设置方法: set NAMESILO_API_KEY=你的key  (Windows)")
        print("           export NAMESILO_API_KEY=你的key (Linux/Mac)")
        sys.exit(1)

    base_url = "https://www.namesilo.com/api/"
    params = params or {}
    params['version'] = '1'
    params['type'] = 'xml'
    params['key'] = NAMESILO_API_KEY

    url = base_url + command + '?' + urllib.parse.urlencode(params)

    try:
        resp = make_http_request(url, timeout=30)
        xml_text = resp.read().decode('utf-8')
        root = ET.fromstring(xml_text)
        reply = root.find('.//reply')
        code = reply.find('code').text if reply.find('code') is not None else ''
        detail = reply.find('detail').text if reply.find('detail') is not None else ''
        return {'code': code, 'detail': detail, 'root': root, 'reply': reply}
    except Exception as e:
        return {'code': 'error', 'detail': str(e), 'root': None, 'reply': None}

def namesilo_add_cname(domain, subdomain, target):
    """在 Namesilo 添加 CNAME 记录"""
    result = namesilo_api('dnsAddRecord', {
        'domain': domain,
        'rrtype': 'CNAME',
        'rrhost': subdomain,
        'rrvalue': target,
        'rrttl': '3600'
    })

    if result['code'] == '300':
        print(f"  ✅ CNAME 创建成功: {subdomain}.{domain} -> {target}")
        return True
    else:
        print(f"  ❌ CNAME 创建失败: {subdomain}.{domain} -> {result['detail']}")
        return False

def namesilo_delete_cname(domain, record_id):
    """删除 Namesilo DNS 记录"""
    result = namesilo_api('dnsDeleteRecord', {
        'domain': domain,
        'rrid': record_id
    })
    return result['code'] == '300'

def namesilo_list_records(domain):
    """列出 Namesilo DNS 记录"""
    result = namesilo_api('dnsListRecords', {'domain': domain})
    records = []
    if result['reply'] is not None:
        for rec in result['reply'].findall('.//resource_record'):
            records.append({
                'id': rec.find('record_id').text if rec.find('record_id') is not None else '',
                'type': rec.find('type').text if rec.find('type') is not None else '',
                'host': rec.find('host').text if rec.find('host') is not None else '',
                'value': rec.find('value').text if rec.find('value') is not None else '',
            })
    return records

# ========== He.net API ==========
def henet_add_cname(domain, subdomain, target):
    """在 He.net 添加 CNAME 记录（通过表单模拟）"""
    if not HENET_API_KEY:
        print("[错误] 未设置 HENET_API_KEY 环境变量")
        sys.exit(1)

    url = "https://dns.he.net/index.cgi"
    params = urllib.parse.urlencode({
        'account': '',
        'menu': 'edit_zone',
        'hosted_dns_zoneid': '',
        'Type': 'CNAME',
        'hosted_dns_recordid': '',
        'hosted_dns_editzone': '1',
        'Name': subdomain + '.' + domain,
        'Content': target + '.',
        'TTL': '3600',
        'hosted_dns_editrecord': 'Submit',
    }).encode()

    try:
        resp = make_http_request(
            url, 
            method='POST', 
            data=params, 
            headers={'Cookie': f'dns_he_net={HENET_API_KEY}'}, 
            timeout=30
        )
        if resp.status == 200:
            print(f"  ✅ CNAME 创建成功: {subdomain}.{domain} -> {target}")
            return True
    except Exception as e:
        print(f"  ❌ CNAME 创建失败: {subdomain}.{domain} -> {e}")
    return False

# ========== deSEC API ==========
def desec_api(method, endpoint, data=None):
    """调用 deSEC API"""
    if not DESEC_TOKEN:
        print("[错误] 未设置 DESEC_TOKEN 环境变量")
        print("  获取方法: desec.io -> Account -> Token Management")
        print("  设置方法: set DESEC_TOKEN=你的token  (Windows)")
        print("           export DESEC_TOKEN=你的token (Linux/Mac)")
        sys.exit(1)

    url = 'https://desec.io/api/v1/' + endpoint
    body = json.dumps(data).encode('utf-8') if data else None

    headers = {
        'Authorization': f'Token {DESEC_TOKEN}',
        'Content-Type': 'application/json'
    }

    try:
        resp = make_http_request(url, method=method, data=body, headers=headers, timeout=30)
        resp_body = resp.read().decode('utf-8')
        return {'ok': True, 'status': resp.status, 'data': json.loads(resp_body) if resp_body else {}}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8') if e.fp else ''
        return {'ok': False, 'status': e.code, 'data': err_body}
    except Exception as e:
        return {'ok': False, 'status': 0, 'data': str(e)}

def desec_add_cname(domain, subdomain, target):
    """在 deSEC 添加 CNAME 记录"""
    # deSEC 的 CNAME value 需要以 . 结尾
    target_fqdn = target if target.endswith('.') else target + '.'
    result = desec_api('POST', f'domains/{domain}/rrsets/', {
        'subname': subdomain,
        'type': 'CNAME',
        'ttl': 3600,
        'records': [target_fqdn]
    })

    if result['ok'] or result['status'] == 201:
        print(f"  ✅ CNAME 创建成功: {subdomain}.{domain} -> {target}")
        return True
    elif result['status'] in (409, 400):
        # 记录已存在，尝试用 PATCH 更新
        result2 = desec_api('PATCH', f'domains/{domain}/rrsets/{subdomain}/CNAME/', {
            'ttl': 3600,
            'records': [target_fqdn]
        })
        if result2['ok'] or result2['status'] == 200:
            print(f"  ✅ CNAME 更新成功: {subdomain}.{domain} -> {target}")
            return True
        else:
            print(f"  ❌ CNAME 更新失败: {subdomain}.{domain} -> {result2['data']}")
            return False
    else:
        print(f"  ❌ CNAME 创建失败: {subdomain}.{domain} -> HTTP {result['status']}: {result['data']}")
        return False

def desec_delete_record(domain, subdomain, rtype='CNAME'):
    """删除 deSEC DNS 记录"""
    result = desec_api('DELETE', f'domains/{domain}/rrsets/{subdomain}/{rtype}/')
    if result['ok'] or result['status'] == 204:
        print(f"  ✅ 删除成功: {subdomain}.{domain} [{rtype}]")
        return True
    else:
        print(f"  ❌ 删除失败: {subdomain}.{domain} -> {result['data']}")
        return False

def desec_list_records(domain):
    """列出 deSEC DNS 记录"""
    result = desec_api('GET', f'domains/{domain}/rrsets/')
    if result['ok']:
        return result['data']
    else:
        print(f"[错误] 获取记录失败: {result['data']}")
        return []

# ========== 批量操作 ==========
def batch_add(provider, domain, subdomains, target):
    """批量创建子域名 + CNAME"""
    print(f"\n{'='*60}")
    print(f"  批量创建 CNAME 记录")
    print(f"  DNS: {provider} | 域名: {domain}")
    print(f"  目标: {target}")
    print(f"  子域名: {', '.join(subdomains)}")
    print(f"{'='*60}\n")

    success = 0
    data = load_domains()
    line_num = len(data['domains']) + 1

    for sub in subdomains:
        full_domain = f"https://{sub}.{domain}"
        name = f"线路{line_num}"

        if provider == 'desec':
            ok = desec_add_cname(domain, sub, target)
        elif provider == 'namesilo':
            ok = namesilo_add_cname(domain, sub, target)
        elif provider == 'henet':
            ok = henet_add_cname(domain, sub, target)
        else:
            print(f"  [错误] 不支持的 DNS 提供商: {provider}")
            continue

        if ok:
            # 添加到域名库
            data['domains'].append({"url": full_domain, "name": name, "provider": provider})
            success += 1
            line_num += 1

        # API 限速，间隔 2 秒
        time.sleep(2)

    save_domains(data)
    print(f"\n[完成] 成功创建 {success}/{len(subdomains)} 条记录")

def rotate_domains(provider, domain, target, count=5):
    """
    轮换域名：生成一批随机子域名，创建 CNAME，替换旧的
    当旧域名被封时使用
    """
    print(f"\n{'='*60}")
    print(f"  🔄 域名轮换 - 生成 {count} 个新随机子域名")
    print(f"{'='*60}\n")

    # 生成随机子域名
    prefixes = ['app', 'web', 'm', 'h5', 'go', 'trade', 'ex', 'pro', 'vip', 'top',
                'fast', 'speed', 'safe', 'new', 'my', 'get', 'hub', 'net', 'link', 'one']
    new_subs = []
    for _ in range(count):
        prefix = random.choice(prefixes)
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=3))
        new_subs.append(f"{prefix}{suffix}")

    # 删除旧的同 provider 域名记录
    data = load_domains()
    old_domains = [d for d in data['domains'] if d.get('provider') == provider]
    if old_domains:
        print(f"  移除 {len(old_domains)} 条旧 {provider} 域名...")
        data['domains'] = [d for d in data['domains'] if d.get('provider') != provider]
        save_domains(data)

    # 创建新的
    batch_add(provider, domain, new_subs, target)

    print(f"\n  新域名列表:")
    data = load_domains()
    for d in data['domains']:
        print(f"    {d['name']:10s} {d['url']}")


def update_site_config(site_name=None, base_domain=None, candidate_count=None, label_length=None,
                       probe_assets=None, probe_asset_threshold=None, wildcard_enabled=None):
    """更新独立跳转站配置"""
    data = load_domains()

    if site_name is not None:
        data['siteName'] = site_name.strip() or data['siteName']
    if base_domain is not None:
        data['wildcard']['baseDomain'] = base_domain.strip()
    if candidate_count is not None:
        data['wildcard']['candidateCount'] = int(candidate_count)
    if label_length is not None:
        data['wildcard']['labelLength'] = int(label_length)
    if wildcard_enabled is not None:
        data['wildcard']['enabled'] = bool(wildcard_enabled)
    if probe_assets is not None:
        data['probeAssets'] = [item.strip() for item in probe_assets if item.strip()]
    if probe_asset_threshold is not None:
        data['probeAssetThreshold'] = int(probe_asset_threshold)

    save_domains(data)
    return data


class GoPageAdminHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def check_auth(self):
        if not ADMIN_PASS:
            return True
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Basic '):
            return False
        try:
            decoded = base64.b64decode(auth[6:]).decode('utf-8')
            user, passwd = decoded.split(':', 1)
            return user == ADMIN_USER and passwd == ADMIN_PASS
        except Exception:
            return False

    def require_auth(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Go Page Admin"')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ('/admin', '/admin/', '/admin.html', '/api/config'):
            if not self.check_auth():
                return self.require_auth()
        if parsed.path == '/api/config':
            return self.send_json(load_domains())
        if parsed.path in ('/admin', '/admin/'):
            self.path = '/admin.html'
        return super().do_GET()

    def do_POST(self):
        if not self.check_auth():
            return self.require_auth()
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != '/api/config':
            self.send_error(404, 'Not Found')
            return

        length = int(self.headers.get('Content-Length', '0') or 0)
        payload = self.rfile.read(length).decode('utf-8') if length else '{}'
        try:
            data = normalize_config(json.loads(payload or '{}'))
        except json.JSONDecodeError as exc:
            self.send_json({'ok': False, 'message': f'JSON 格式错误: {exc}'}, status=400)
            return

        save_domains(data)
        self.send_json({'ok': True, 'message': '配置已保存', 'config': load_domains()})

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print('[admin]', format % args)


def serve_admin(host=None, port=None):
    """启动 go_page 独立后台"""
    host = host or os.environ.get('HOST', '0.0.0.0')
    port = port or int(os.environ.get('PORT', '8787'))
    server = ThreadingHTTPServer((host, port), GoPageAdminHandler)
    print(f"[OK] 独立后台已启动: http://{host}:{port}/admin")
    print(f"[OK] 落地页预览: http://{host}:{port}/index.html")
    if ADMIN_PASS:
        print(f"[OK] 后台鉴权已启用 (用户: {ADMIN_USER})")
    else:
        print("[WARN] 未设置 ADMIN_PASS，后台无鉴权保护")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n[STOP] 后台已停止')
    finally:
        server.server_close()

# ========== 主入口 ==========
def main():
    parser = argparse.ArgumentParser(
        description='KVI 域名管理工具 - 批量创建/检测/轮换域名',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 检测所有域名
  python manage_domains.py check

  # 在 Namesilo 批量创建 4 个子域名
  python manage_domains.py add --provider namesilo --domain mysite.xyz --subs "app,www,m,h5" --target kiv.up.railway.app

  # 域名被封了？一键换一批新的（随机生成5个）
  python manage_domains.py rotate --provider namesilo --domain mysite.xyz --target kiv.up.railway.app --count 5

  # 手动移除域名
  python manage_domains.py remove --urls "https://app.mysite.xyz,https://www.mysite.xyz"

  # 列出域名库
  python manage_domains.py list

    # 启动 go_page 独立后台
    python manage_domains.py serve-admin --port 8787

    # 修改独立跳转站当前配置
    python manage_domains.py site-set --site-name "新站点" --base-domain example.com --assets "/static/a.png,/static/b.png"

环境变量:
  DESEC_TOKEN       - deSEC API Token (推荐)
  NAMESILO_API_KEY  - Namesilo API 密钥
  HENET_API_KEY     - He.net DNS Session Cookie
  ADMIN_USER        - 后台用户名 (默认 admin)
  ADMIN_PASS        - 后台密码 (未设置则不启用鉴权)
  PORT              - 监听端口 (Railway 自动设置)
  HOST              - 监听地址 (默认 0.0.0.0)
        """
    )

    sub = parser.add_subparsers(dest='command', help='操作命令')

    # check
    sub.add_parser('check', help='检测所有域名可用性')

    # list
    sub.add_parser('list', help='列出域名库')

    # add
    p_add = sub.add_parser('add', help='批量添加子域名')
    p_add.add_argument('--provider', required=True, choices=['desec', 'namesilo', 'henet'], help='DNS 提供商')
    p_add.add_argument('--domain', required=True, help='主域名 (如 mysite.xyz)')
    p_add.add_argument('--subs', required=True, help='子域名列表，逗号分隔 (如 "app,www,m")')
    p_add.add_argument('--target', required=True, help='CNAME 目标 (如 kiv.up.railway.app)')

    # remove
    p_rm = sub.add_parser('remove', help='移除域名')
    p_rm.add_argument('--urls', required=True, help='要移除的 URL，逗号分隔')

    # rotate
    p_rot = sub.add_parser('rotate', help='轮换域名（旧的删掉，生成新的随机子域名）')
    p_rot.add_argument('--provider', required=True, choices=['desec', 'namesilo', 'henet'], help='DNS 提供商')
    p_rot.add_argument('--domain', required=True, help='主域名')
    p_rot.add_argument('--target', required=True, help='CNAME 目标')
    p_rot.add_argument('--count', type=int, default=5, help='生成几个新子域名 (默认5)')

    # dns-list (列出 DNS 记录)
    p_dns = sub.add_parser('dns-list', help='列出 DNS 记录')
    p_dns.add_argument('--domain', required=True, help='域名')
    p_dns.add_argument('--provider', default='desec', choices=['desec', 'namesilo'], help='DNS 提供商 (默认 desec)')

    # serve-admin
    p_admin = sub.add_parser('serve-admin', help='启动 go_page 独立后台')
    p_admin.add_argument('--host', default=None, help='监听地址 (默认 0.0.0.0，或 HOST 环境变量)')
    p_admin.add_argument('--port', type=int, default=None, help='监听端口 (默认 8787，或 PORT 环境变量)')

    # site-set
    p_site = sub.add_parser('site-set', help='设置 go_page 当前站点配置')
    p_site.add_argument('--site-name', help='站点名称')
    p_site.add_argument('--base-domain', help='通配基础域名，如 a-hui-od.top')
    p_site.add_argument('--candidate-count', type=int, help='随机候选域名数量')
    p_site.add_argument('--label-length', type=int, help='随机前缀长度')
    p_site.add_argument('--assets', help='站点资源路径，逗号分隔')
    p_site.add_argument('--asset-threshold', type=int, help='资源命中阈值')
    p_site.add_argument('--disable-wildcard', action='store_true', help='关闭通配模式，改用 domains 列表')

    args = parser.parse_args()

    if args.command == 'check':
        check_all()
    elif args.command == 'list':
        data = load_domains()
        print(f"\n域名库 (更新于: {data.get('updated', '未知')})")
        print(f"{'='*60}")
        for i, d in enumerate(data['domains'], 1):
            print(f"  {i}. {d['name']:10s} {d['url']:40s} [{d.get('provider','')}]")
        print(f"\n共 {len(data['domains'])} 条\n")
    elif args.command == 'add':
        subs = [s.strip() for s in args.subs.split(',') if s.strip()]
        batch_add(args.provider, args.domain, subs, args.target)
    elif args.command == 'remove':
        urls = [u.strip() for u in args.urls.split(',') if u.strip()]
        remove_from_domains(urls)
    elif args.command == 'rotate':
        rotate_domains(args.provider, args.domain, args.target, args.count)
    elif args.command == 'dns-list':
        if args.provider == 'desec':
            records = desec_list_records(args.domain)
            print(f"\nDNS 记录 ({args.domain}) [deSEC]:")
            for r in records:
                subname = r.get('subname', '@') or '@'
                rtype = r.get('type', '')
                recs = r.get('records', [])
                print(f"  [{rtype:6s}] {subname:30s} -> {', '.join(recs)}")
        else:
            records = namesilo_list_records(args.domain)
            print(f"\nDNS 记录 ({args.domain}) [Namesilo]:")
            for r in records:
                print(f"  [{r['type']:6s}] {r['host']:30s} -> {r['value']:30s} (ID: {r['id']})")
    elif args.command == 'serve-admin':
        serve_admin(args.host, args.port)
    elif args.command == 'site-set':
        assets = None
        if args.assets is not None:
            assets = [item for item in args.assets.split(',')]
        data = update_site_config(
            site_name=args.site_name,
            base_domain=args.base_domain,
            candidate_count=args.candidate_count,
            label_length=args.label_length,
            probe_assets=assets,
            probe_asset_threshold=args.asset_threshold,
            wildcard_enabled=False if args.disable_wildcard else None,
        )
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        if os.environ.get('PORT') or os.environ.get('RAILWAY_ENVIRONMENT'):
            serve_admin()
        else:
            parser.print_help()

if __name__ == '__main__':
    main()
