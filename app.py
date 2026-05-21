import os
import json
import base64
import binascii
import gzip
import zlib
import threading
import time
import urllib3
import requests as http_requests
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from Crypto.Cipher import AES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

ITEM_DATA_FILE = "data.json"
item_name_cache = {}

def load_item_database():
    global item_name_cache
    if os.path.exists(ITEM_DATA_FILE):
        try:
            with open(ITEM_DATA_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for entry in data:
                    item_id = entry.get("itemID")
                    name = entry.get("name")
                    typ = entry.get("type", "")
                    if item_id is not None and name is not None:
                        item_name_cache[item_id] = (name, typ)
            print(f"Loaded {len(item_name_cache)} items from {ITEM_DATA_FILE}")
        except Exception as e:
            print(f"Warning: failed to load item data: {e}")
    else:
        print(f"No item database found at {ITEM_DATA_FILE}, using raw IDs")

def get_item_info(item_id):
    if item_id in item_name_cache:
        name, typ = item_name_cache[item_id]
        return f"ID {item_id} - ({typ} - {name})" if typ else f"ID {item_id} - {name}"
    return f"ID {item_id}"

def encode_varint(value: int) -> bytes:
    out = []
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def build_payload_from_dict(fields_dict: Dict[int, Any]) -> bytes:
    payload = b''
    for key, value in sorted(fields_dict.items()):
        field_num = int(key)
        if isinstance(value, bool):
            tag = (field_num << 3) | 0
            payload += encode_varint(tag)
            payload += encode_varint(1 if value else 0)
        elif isinstance(value, int):
            tag = (field_num << 3) | 0
            payload += encode_varint(tag)
            payload += encode_varint(value)
        elif isinstance(value, str):
            tag = (field_num << 3) | 2
            data = value.encode('utf-8')
            payload += encode_varint(tag)
            payload += encode_varint(len(data))
            payload += data
        else:
            raise TypeError(f"Unsupported type for field {field_num}")
    return payload

def encrypt_packet(plaintext: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    pad = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad]) * pad
    return cipher.encrypt(plaintext)

def decrypt_payload(hex_payload: str) -> bytes:
    ciphertext = bytes.fromhex(hex_payload)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted = cipher.decrypt(ciphertext)
    pad = decrypted[-1]
    if 1 <= pad <= 16:
        return decrypted[:-pad]
    return decrypted

def decode_protobuf(data: bytes) -> Dict:
    pos = 0
    length = len(data)
    fields = {}
    while pos < length:
        key, pos = _decode_varint(data, pos)
        field_number = key >> 3
        wire_type = key & 7
        if wire_type == 0:
            value, pos = _decode_varint(data, pos)
        elif wire_type == 2:
            size, pos = _decode_varint(data, pos)
            raw = data[pos:pos+size]
            pos += size
            try:
                value = decode_protobuf(raw)
            except:
                value = raw.hex()
        elif wire_type == 5:
            value = int.from_bytes(data[pos:pos+4], 'little')
            pos += 4
        elif wire_type == 1:
            value = int.from_bytes(data[pos:pos+8], 'little')
            pos += 8
        else:
            raise ValueError(f"Unsupported wire type {wire_type}")
        if field_number in fields:
            if not isinstance(fields[field_number], list):
                fields[field_number] = [fields[field_number]]
            fields[field_number].append(value)
        else:
            fields[field_number] = value
    return fields

def _decode_varint(data: bytes, pos: int):
    result = 0
    shift = 0
    while True:
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, pos

def decompress_response(resp) -> bytes:
    content_encoding = resp.headers.get('Content-Encoding', '').lower()
    raw = resp.content
    if content_encoding == 'gzip':
        try:
            return gzip.decompress(raw)
        except:
            return raw
    elif content_encoding == 'deflate':
        try:
            return zlib.decompress(raw)
        except:
            return raw
    return raw

def decode_jwt(token: str) -> Dict:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT")
    payload = parts[1]
    missing = len(payload) % 4
    if missing:
        payload += '=' * (4 - missing)
    payload = payload.replace('-', '+').replace('_', '/')
    decoded = base64.b64decode(payload)
    return json.loads(decoded)

def get_hosts(region: str) -> List[str]:
    region_hosts = {
        "IND": ["client.ind.freefiremobile.com"],
        "BD":  ["clientbp.ggpolarbear.com"],
        "ME":  ["clientbp.ggpolarbear.com"],
        "PK":  ["clientbp.ggblueshark.com"],
        "BR":  ["client.us.freefiremobile.com"],
        "US":  ["client.us.freefiremobile.com"],
        "NA":  ["client.us.freefiremobile.com"],
        "SAC": ["client.us.freefiremobile.com"],
        "VN":  ["clientbp.ggpolarbear.com"],
        "SG":  ["clientbp.ggpolarbear.com"],
        "ID":  ["clientbp.ggpolarbear.com"],
        "RU":  ["clientbp.ggpolarbear.com"],
        "TH":  ["clientbp.ggpolarbear.com"],
    }
    return region_hosts.get(region, ["clientbp.ggpolarbear.com"])

def send_request(endpoint: str, body_bytes: bytes, headers: Dict, hosts: List[str]):
    for host in hosts:
        url = f"https://{host}{endpoint}"
        headers_copy = headers.copy()
        headers_copy["Host"] = host
        headers_copy["Content-Length"] = str(len(body_bytes))
        try:
            resp = http_requests.post(url, headers=headers_copy, data=body_bytes,
                                      timeout=15, verify=False)
            raw = decompress_response(resp)
            decoded = decode_protobuf(raw) if resp.status_code == 200 else None
            return resp.status_code, decoded, raw
        except Exception as e:
            print(f"Request error to {host}: {e}")
            continue
    return None, None, None

def fetch_gacha_desc(hosts: List[str], headers: Dict):
    body_hex = "1A725B2C56EC52BA7D09623454C0A003"
    body_bytes = binascii.unhexlify(body_hex)
    status, decoded, _ = send_request("/GetGachaDesc", body_bytes, headers, hosts)
    if status == 200 and decoded:
        return decoded
    return None

class GachaEventPayload(BaseModel):
    event_id: int
    event_name: str
    encrypted_hex: str
    payload_fields: Dict[int, Any]
    rare_items: List[str]

class GenerateResponse(BaseModel):
    status: str
    region: str
    events: List[GachaEventPayload]

class SpinResult(BaseModel):
    event_id: int
    event_name: str
    status_code: int
    is_free: bool
    encrypted_hex: str
    decoded_response: Optional[Dict] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    load_item_database()
    thread = threading.Thread(target=self_pinger, daemon=True)
    thread.start()
    yield

app = FastAPI(title="Free Fire Auto Spin Tester", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/generate", response_model=GenerateResponse)
async def generate_payloads(jwt: str = Query(..., description="JWT token from Free Fire")):
    try:
        payload = decode_jwt(jwt)
        lock_region = payload.get("lock_region", "")
        if not lock_region:
            raise HTTPException(status_code=400, detail="lock_region not found in JWT")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JWT: {str(e)}")

    hosts = get_hosts(lock_region)
    base_headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2022.3.47f1",
        "Authorization": f"Bearer {jwt}"
    }

    gacha_desc = fetch_gacha_desc(hosts, base_headers)
    if not gacha_desc:
        raise HTTPException(status_code=502, detail="Failed to fetch GachaDesc from game servers")

    events_data = gacha_desc.get(1, [])
    if not events_data:
        raise HTTPException(status_code=404, detail="No events found in GachaDesc")

    result_events = []
    for event in events_data:
        event_id = event[2][1]
        raw_name = event[2][6]
        if isinstance(raw_name, bytes):
            event_name = raw_name.decode('utf-8', errors='replace')
        else:
            event_name = str(raw_name)
        field3 = event[2][39]

        prize_list = []
        if 3 in event and 1 in event[3]:
            prize_list = event[3][1][:3]
        rare_items = []
        for i, prize in enumerate(prize_list, 1):
            item_id = prize.get(1) if isinstance(prize, dict) else None
            if item_id:
                rare_items.append(f"{get_item_info(item_id)} (Index: {i})")
            else:
                rare_items.append(f"ID ??? (Index: {i})")

        msg = {
            1: event_id,
            2: 1,
            3: field3,
            4: 1,
            7: 0,
            8: False,
            9: 0,
            10: 0,
            11: 0,
            13: 1
        }
        plain = build_payload_from_dict(msg)
        encrypted = encrypt_packet(plain)
        encrypted_hex = encrypted.hex().upper()

        result_events.append(GachaEventPayload(
            event_id=event_id,
            event_name=event_name,
            encrypted_hex=encrypted_hex,
            payload_fields=msg,
            rare_items=rare_items
        ))

    return GenerateResponse(status="success", region=lock_region, events=result_events)

@app.post("/spin", response_model=List[SpinResult])
async def spin_events(jwt: str = Query(..., description="JWT token from Free Fire")):
    try:
        payload = decode_jwt(jwt)
        lock_region = payload.get("lock_region", "")
        if not lock_region:
            raise HTTPException(status_code=400, detail="lock_region not found in JWT")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JWT: {str(e)}")

    hosts = get_hosts(lock_region)
    base_headers = {
        "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB53",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2022.3.47f1",
        "Authorization": f"Bearer {jwt}"
    }

    gacha_desc = fetch_gacha_desc(hosts, base_headers)
    if not gacha_desc:
        raise HTTPException(status_code=502, detail="Failed to fetch GachaDesc from game servers")

    events_data = gacha_desc.get(1, [])
    if not events_data:
        raise HTTPException(status_code=404, detail="No events found in GachaDesc")

    results = []
    for event in events_data:
        event_id = event[2][1]
        raw_name = event[2][6]
        if isinstance(raw_name, bytes):
            event_name = raw_name.decode('utf-8', errors='replace')
        else:
            event_name = str(raw_name)
        field3 = event[2][39]

        msg = {
            1: event_id,
            2: 1,
            3: field3,
            4: 1,
            7: 0,
            8: False,
            9: 0,
            10: 0,
            11: 0,
            13: 1
        }
        plain = build_payload_from_dict(msg)
        encrypted = encrypt_packet(plain)
        encrypted_hex = encrypted.hex().upper()

        status_code, decoded, _ = send_request("/PurchaseGacha", encrypted, base_headers, hosts)
        is_free = (status_code == 200)

        results.append(SpinResult(
            event_id=event_id,
            event_name=event_name,
            status_code=status_code if status_code is not None else 0,
            is_free=is_free,
            encrypted_hex=encrypted_hex,
            decoded_response=decoded
        ))

    return results

def sanitize_html(html: str) -> str:
    return html.encode('utf-8', errors='ignore').decode('utf-8')

@app.get("/", response_class=HTMLResponse)
async def frontend():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Free Fire Auto Spin Tester</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        .spinner { border: 3px solid #f3f3f3; border-top: 3px solid #3b82f6; border-radius: 50%; width: 24px; height: 24px; animation: spin 1s linear infinite; display: inline-block; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .debug-log { background: #1e1e2f; color: #f0f0f0; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 12px; max-height: 200px; overflow-y: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f2f2f2; }
        .free { color: green; font-weight: bold; }
        .paid { color: red; font-weight: bold; }
    </style>
</head>
<body class="bg-gray-100 p-6">
    <div class="max-w-6xl mx-auto bg-white rounded-xl shadow-lg overflow-hidden">
        <div class="bg-gradient-to-r from-blue-600 to-purple-600 p-6 text-white">
            <h1 class="text-2xl font-bold"><i class="fas fa-sync-alt"></i> Free Fire Auto Spin Tester</h1>
            <p>Enter JWT → automatically fetch events, attempt spins, and see free/paid status</p>
        </div>
        <div class="p-6">
            <textarea id="jwt" rows="3" class="w-full border rounded p-3 font-mono text-sm" placeholder="Paste JWT token here..."></textarea>
            <div class="mt-4 flex gap-3">
                <button id="spinBtn" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-semibold"><i class="fas fa-play"></i> Check & Spin</button>
                <button id="clearDebugBtn" class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg">Clear Log</button>
            </div>
            <div class="mt-6">
                <h2 class="text-xl font-bold mb-2"><i class="fas fa-chart-simple"></i> Results</h2>
                <div id="results" class="overflow-x-auto"></div>
            </div>
            <div class="mt-6">
                <h2 class="text-xl font-bold mb-2"><i class="fas fa-terminal"></i> Debug Console</h2>
                <div id="debugLog" class="debug-log"></div>
            </div>
        </div>
    </div>
    <script>
        const debugDiv = document.getElementById('debugLog');
        function addDebug(msg, type='info') {
            const time = new Date().toLocaleTimeString();
            const colors = {info:'#aaa', success:'#8f8', error:'#f88', warning:'#fa4'};
            const color = colors[type] || '#fff';
            const line = document.createElement('div');
            line.innerHTML = `<span style="color:#888;">[${time}]</span> <span style="color:${color};">${msg}</span>`;
            debugDiv.appendChild(line);
            debugDiv.scrollTop = debugDiv.scrollHeight;
        }
        async function spin() {
            const jwt = document.getElementById('jwt').value.trim();
            if (!jwt) { alert('Please enter JWT'); return; }
            const btn = document.getElementById('spinBtn');
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner"></span> Working...';
            document.getElementById('results').innerHTML = '<div class="text-center py-4"><span class="spinner"></span> Fetching events and spinning...</div>';
            addDebug('Sending spin request...', 'info');
            try {
                const resp = await fetch(`/spin?jwt=${encodeURIComponent(jwt)}`, { method: 'POST' });
                const data = await resp.json();
                if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
                displayResults(data);
                addDebug(`Completed. Free spins: ${data.filter(e=>e.is_free).length}/${data.length}`, 'success');
            } catch(err) {
                addDebug(`Error: ${err.message}`, 'error');
                document.getElementById('results').innerHTML = `<div class="bg-red-100 text-red-700 p-3 rounded">Error: ${err.message}</div>`;
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-play"></i> Check & Spin';
            }
        }
        function displayResults(events) {
            if (!events.length) {
                document.getElementById('results').innerHTML = '<div class="bg-yellow-100 p-3 rounded">No events found.</div>';
                return;
            }
            let html = '<table class="min-w-full border"><thead><tr><th>Event Name</th><th>Status</th><th>Encrypted Payload (hex)</th><th>Copy</th></tr></thead><tbody>';
            for (const ev of events) {
                const statusClass = ev.is_free ? 'free' : 'paid';
                const statusText = ev.is_free ? 'FREE SPIN' : `PAID (HTTP ${ev.status_code})`;
                html += `<tr>
                    <td class="border p-2">${escapeHtml(ev.event_name)}</td>
                    <td class="border p-2 ${statusClass}">${statusText}</td>
                    <td class="border p-2"><code class="text-xs break-all">${ev.encrypted_hex}</code></td>
                    <td class="border p-2 text-center"><button onclick="copyHex('${ev.encrypted_hex}')" class="text-blue-500"><i class="far fa-copy"></i></button></td>
                </tr>`;
            }
            html += '</tbody></table>';
            document.getElementById('results').innerHTML = html;
        }
        function copyHex(hex) {
            navigator.clipboard.writeText(hex).then(() => addDebug('Copied hex!', 'success')).catch(() => alert('Copy failed'));
        }
        function escapeHtml(str) {
            return str.replace(/[&<>]/g, function(m) {
                if(m === '&') return '&amp;';
                if(m === '<') return '&lt;';
                if(m === '>') return '&gt;';
                return m;
            });
        }
        document.getElementById('spinBtn').onclick = spin;
        document.getElementById('clearDebugBtn').onclick = () => { debugDiv.innerHTML = ''; addDebug('Debug cleared', 'info'); };
        addDebug('Ready. Paste JWT and click "Check & Spin".', 'success');
    </script>
</body>
</html>
    """
    clean_html = sanitize_html(html_content)
    return HTMLResponse(content=clean_html, media_type="text/html; charset=utf-8")

@app.get("/ping")
async def ping():
    return {"status": "alive"}

def self_pinger():
    time.sleep(30)
    while True:
        try:
            url = os.environ.get("RENDER_EXTERNAL_URL")
            if not url:
                url = "http://localhost:8000"
            http_requests.get(f"{url}/ping", timeout=5)
            print(f"Self-ping sent at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as e:
            print(f"Self-ping failed: {e}")
        time.sleep(180)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
