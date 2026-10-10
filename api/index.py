from flask import Flask, request, Response
import requests
import json
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

LOGIN_SERVER = 'https://loginbp.ppmainecoonghj.com'
INSPECT_URL = 'https://100067.connect.garena.com/oauth/token/inspect'
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

PLATFORM_TO_REGION = {
    1: 'ID', 2: 'TH', 3: 'VN', 4: 'BD', 5: 'BR', 6: 'IN', 7: 'PK',
    8: 'EG', 9: 'SA', 10: 'RU', 11: 'MX', 12: 'SG', 13: 'MY',
    14: 'PH', 15: 'TW', 16: 'HK',
}

# ── Simple in-memory cache (per warm instance) ──
_TOKEN_CACHE = {}

# ── 🎯 Alternate logo কাউন্টার (per token) ──
_MAJORLOGIN_COUNT = {}


# =============================================================================
# 🎨 ARIYAN LOGO POPUP
# =============================================================================
def build_ariyan_logo_popup():
    return (
        "[b][c][00FFFF]"
        "╔══════════════════════════════════════╗\n"
        "║  [00FF00]YOUR ID ☠️UNBAN PROSES☠️SUCCESSFUL[00FFFF]       ║\n"
        "╚══════════════════════════════════════╝\n"
        "\n"
        "[FFFF00]╔══════════════════════════════════════╗\n"
        "║  [FF1493]https://t.me/Premiume_FF_Tcp_bot_Community[FFFF00]  ║\n"
        "╚══════════════════════════════════════╝\n"
        "\n"
        "[00FF00]     FILE REAL ADMIN\n"
        "[FF1493]        @AriyanPrime_A9✅x\n"
    )


# =============================================================================
# 🎯 Alternate decision (홀짝)
# =============================================================================
def should_show_logo(token: str) -> bool:
    if not token:
        return False
    count = _MAJORLOGIN_COUNT.get(token, 0) + 1
    _MAJORLOGIN_COUNT[token] = count

    if len(_MAJORLOGIN_COUNT) > 200:
        _MAJORLOGIN_COUNT.pop(next(iter(_MAJORLOGIN_COUNT)))

    is_odd = (count % 2 == 1)
    print(f'[ARIYAN] hit #{count} → '
          f'{"🎨 LOGO" if is_odd else "🔐 LOGIN"}')
    return is_odd


def inspect_token(tok: str):
    """Return dict with open_id/platform/region or None."""
    if not tok or len(tok) != 64:
        return None
    if tok in _TOKEN_CACHE:
        return _TOKEN_CACHE[tok]
    try:
        r = requests.get(INSPECT_URL, params={'token': tok},
                         verify=False, timeout=10)
        if r.status_code != 200:
            return None
        d = r.json()
        plat = int(d.get('platform', 4))
        main_active = int(d.get('main_active_platform', plat))
        region = PLATFORM_TO_REGION.get(main_active, 'BD')
        info = {
            'access_token': tok,
            'open_id': d.get('open_id'),
            'uid': d.get('uid'),
            'platform': plat,
            'main_active': main_active,
            'region': region,
        }
        _TOKEN_CACHE[tok] = info
        if len(_TOKEN_CACHE) > 100:
            _TOKEN_CACHE.pop(next(iter(_TOKEN_CACHE)))
        return info
    except Exception as e:
        print(f'[inspect] error: {e}')
        return None


def aes_decrypt(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    dec = cipher.decrypt(data)
    padlen = dec[-1]
    if 1 <= padlen <= 16 and all(b == padlen for b in dec[-padlen:]):
        dec = dec[:-padlen]
    return dec


def aes_encrypt(data: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))


def read_varint(data, pos):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 127) << shift
        if not (b & 128):
            return (result, pos)
        shift += 7
    return (result, pos)


def encode_varint(num: int) -> bytes:
    out = []
    while True:
        b = num & 127
        num >>= 7
        if num:
            b |= 128
        out.append(b)
        if not num:
            return bytes(out)


def parse_proto_ordered(raw: bytes):
    fields = []
    pos = 0
    while pos < len(raw):
        tag, pos = read_varint(raw, pos)
        fn = tag >> 3
        wt = tag & 7
        if fn == 0 or fn > 536870911:
            raise ValueError('bad field')
        if wt == 0:
            val, pos = read_varint(raw, pos)
            fields.append((fn, wt, val))
        elif wt == 1:
            if pos + 8 > len(raw):
                raise ValueError('short 64')
            val = raw[pos:pos + 8]
            pos += 8
            fields.append((fn, wt, val))
        elif wt == 2:
            length, pos = read_varint(raw, pos)
            if pos + length > len(raw):
                raise ValueError('short ld')
            val = raw[pos:pos + length]
            pos += length
            fields.append((fn, wt, val))
        elif wt == 5:
            if pos + 4 > len(raw):
                raise ValueError('short 32')
            val = raw[pos:pos + 4]
            pos += 4
            fields.append((fn, wt, val))
        else:
            raise ValueError(f'bad wt {wt}')
    return fields


def encode_field(fn, wt, val):
    if wt == 0:
        return encode_varint(fn << 3 | 0) + encode_varint(val)
    elif wt == 1:
        return encode_varint(fn << 3 | 1) + val
    elif wt == 2:
        return encode_varint(fn << 3 | 2) + encode_varint(len(val)) + val
    elif wt == 5:
        return encode_varint(fn << 3 | 5) + val
    raise ValueError(wt)


def try_parse_proto(raw: bytes):
    try:
        return parse_proto_ordered(raw)
    except Exception:
        return None


def rewrite_majorlogin(plain, open_id, access_token, region, platform, main_active):
    fields = parse_proto_ordered(plain)
    seen = set()
    out = []
    for fn, wt, val in fields:
        seen.add(fn)
        if fn == 22 and wt == 2:
            val = open_id.encode()
        elif fn == 26 and wt == 2:
            val = region.encode()
        elif fn == 29 and wt == 2:
            val = access_token.encode()
        elif fn == 99 and wt == 2:
            val = str(platform).encode()
        elif fn == 100 and wt == 2:
            val = str(main_active).encode()
        out.append(encode_field(fn, wt, val))

    if 22 not in seen:
        out.append(encode_field(22, 2, open_id.encode()))
    if 26 not in seen:
        out.append(encode_field(26, 2, region.encode()))
    if 29 not in seen:
        out.append(encode_field(29, 2, access_token.encode()))
    if 99 not in seen:
        out.append(encode_field(99, 2, str(platform).encode()))
    if 100 not in seen:
        out.append(encode_field(100, 2, str(main_active).encode()))
    return b''.join(out)


def forward_to_endpoint(endpoint: str, query_string: bytes = b'', tok: str = ''):
    endpoint = endpoint.lstrip('/')

    # ── 🎨 Alternate লোগো চেক (শুধু MajorLogin/guest/camera) ──
    ep_lower = endpoint.lower()
    is_logo_endpoint = any(k in ep_lower for k in (
        'majorlogin', 'major_login',
        'guestlogin', 'guest_login', 'guest',
        'cameralogin', 'camera_login',
        'prelogin', 'pre_login',
        'getlogindata',
        'checklogin', 'check_login',
        'initlogin', 'init_login',
        'startlogin', 'start_login',
    ))

    if tok and is_logo_endpoint and should_show_logo(tok):
        return Response(
            build_ariyan_logo_popup(),
            status=500,
            mimetype='application/octet-stream',
        )

    target_url = f'{LOGIN_SERVER}/{endpoint}'
    if query_string:
        target_url = f"{target_url}?{query_string.decode('utf-8', 'replace')}"

    excluded_headers = [
        'host', 'content-length', 'accept-encoding',
        'connection', 'transfer-encoding',
    ]
    forward_headers = {k: v for k, v in request.headers
                       if k.lower() not in excluded_headers}
    forward_headers['Accept-Encoding'] = 'identity'

    req_body = request.get_data()

    info = inspect_token(tok) if tok else None

    is_majorlogin = 'majorlogin' in endpoint.lower()
    if is_majorlogin and info:
        plain = None
        if len(req_body) >= 16 and len(req_body) % 16 == 0:
            try:
                dec = aes_decrypt(req_body)
                if try_parse_proto(dec):
                    plain = dec
            except Exception:
                pass
        if plain is None and try_parse_proto(req_body):
            plain = req_body

        if plain is not None:
            try:
                new_plain = rewrite_majorlogin(
                    plain,
                    info['open_id'],
                    info['access_token'],
                    info['region'],
                    info['platform'],
                    info['main_active'],
                )
                req_body = aes_encrypt(new_plain)
                print(f"[MajorLogin] rewritten region={info['region']} "
                      f"plat={info['platform']} oid={info['open_id'][:10]}...")
            except Exception as e:
                print(f'[MajorLogin] rewrite failed: {e}')

    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            data=req_body,
            cookies=request.cookies,
            allow_redirects=False,
            stream=False,
            verify=False,
            timeout=(5, 25),
        )
        resp_body = resp.content

        response_excluded_headers = [
            'content-encoding', 'content-length',
            'transfer-encoding', 'connection',
        ]
        response_headers = [
            (name, value) for name, value in resp.raw.headers.items()
            if name.lower() not in response_excluded_headers
        ]
        return Response(resp_body, status=resp.status_code, headers=response_headers)

    except requests.exceptions.ConnectTimeout:
        return Response('Upstream connect timeout', status=504)
    except requests.exceptions.ReadTimeout:
        return Response('Upstream read timeout', status=504)
    except requests.exceptions.RequestException as e:
        print(f'[ERROR] {request.method} /{endpoint} - {e}')
        return Response('Proxy Error', status=502)


def extract_token():
    return (request.args.get('unben')
            or request.args.get('access_token')
            or request.args.get('token')
            or '').strip()


# =============================================================================
# 🎯 ROUTES
# =============================================================================
@app.route('/id', methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'])
def id_route():
    tok_raw = extract_token()
    if not tok_raw:
        return Response('Missing ?unben=...', status=400)
    if len(tok_raw) < 64:
        return Response(f'Token too short ({len(tok_raw)})', status=400)

    token = tok_raw[:64]
    endpoint = tok_raw[64:].strip('/')

    info = inspect_token(token)
    if not info:
        return Response('Token inspect failed', status=401)

    if not endpoint:
        return Response('OK', status=200)
    return forward_to_endpoint(endpoint, b'', token)


@app.route('/login', methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'])
def login():
    tok_raw = extract_token()
    if not tok_raw:
        return Response('Missing ?unben=...', status=400)
    if len(tok_raw) < 64:
        return Response(f'Token too short ({len(tok_raw)})', status=400)

    token = tok_raw[:64]
    endpoint = tok_raw[64:].strip('/')

    info = inspect_token(token)
    if not info:
        return Response('Token inspect failed', status=401)

    if not endpoint:
        return Response('OK', status=200)
    return forward_to_endpoint(endpoint, b'', token)


@app.route('/', defaults={'path': ''},
           methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'])
@app.route('/<path:path>',
           methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'])
def proxy(path):
    tok = extract_token()
    if not path:
        return Response('OK', status=200)
    return forward_to_endpoint(path, request.query_string, tok[:64])


# Vercel handler
handler = app
