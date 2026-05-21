import os
import json
import base64
import binascii
import gzip
import zlib
import threading
import time
import traceback
import urllib3
import requests as http_requests
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
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

app = FastAPI(title="Free Fire Gacha Tool", lifespan=lifespan)

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
            status_code=status_code or 0,
            is_free=is_free,
            encrypted_hex=encrypted_hex,
            decoded_response=decoded
        ))

    return results

def sanitize_html(html: str) -> str:
    """Remove any invalid Unicode surrogate characters."""
    return html.encode('utf-8', errors='ignore').decode('utf-8')

@app.get("/", response_class=HTMLResponse)
async def frontend():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
    <title>Free Fire Gacha Tool - Payload Generator & Spin Tester</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        pre { white-space: pre-wrap; word-wrap: break-word; }
        .debug-log { font-family: 'Courier New', monospace; font-size: 12px; background: #1e1e2f; color: #f0f0f0; padding: 12px; border-radius: 8px; max-height: 300px; overflow-y: auto; }
        .copy-btn { cursor: pointer; transition: all 0.2s; }
        .copy-btn:hover { transform: scale(1.05); }
        .tab-active { border-bottom: 2px solid #3b82f6; color: #3b82f6; }
        .spinner { border: 3px solid #f3f3f3; border-top: 3px solid #3b82f6; border-radius: 50%; width: 24px; height: 24px; animation: spin 1s linear infinite; display: inline-block; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body class="bg-gray-100 font-sans">
    <div class="container mx-auto px-4 py-8 max-w-6xl">
        <div class="bg-white rounded-2xl shadow-xl overflow-hidden">
            <div class="bg-gradient-to-r from-blue-600 to-purple-600 p-6 text-white">
                <h1 class="text-3xl font-bold flex items-center gap-3">
                    <i class="fas fa-gamepad"></i> Free Fire Gacha Tool
                </h1>
                <p class="mt-2 opacity-90">Generate encrypted PurchaseGacha payloads or test spins (free/paid)</p>
            </div>

            <div class="p-6">
                <div class="mb-6">
                    <label class="block text-gray-700 font-semibold mb-2">JWT Token</label>
                    <textarea id="jwt" rows="3" class="w-full border border-gray-300 rounded-lg p-3 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="Paste your JWT token here..."></textarea>
                    <p class="text-xs text-gray-500 mt-1">Token is never stored, only used for API calls.</p>
                </div>

                <div class="flex flex-wrap gap-4 mb-6 border-b pb-2">
                    <button id="tabGenerate" class="tab-btn py-2 px-4 font-semibold text-gray-600 hover:text-blue-600 transition"><i class="fas fa-box"></i> Generate Payloads (No spin)</button>
                    <button id="tabSpin" class="tab-btn py-2 px-4 font-semibold text-gray-600 hover:text-blue-600 transition"><i class="fas fa-dice-d6"></i> Spin & Test (Uses spins!)</button>
                    <button id="tabDebug" class="tab-btn py-2 px-4 font-semibold text-gray-600 hover:text-blue-600 transition"><i class="fas fa-bug"></i> Debug Console</button>
                </div>

                <div id="panelGenerate" class="panel">
                    <button id="btnGenerate" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded-lg transition flex items-center gap-2">
                        <i class="fas fa-key"></i> Generate Encrypted Payloads
                    </button>
                </div>

                <div id="panelSpin" class="panel hidden">
                    <button id="btnSpin" class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-6 rounded-lg transition flex items-center gap-2">
                        <i class="fas fa-dice-d6"></i> Perform Spins (WARNING: consumes spins!)
                    </button>
                    <p class="text-xs text-red-500 mt-2"><i class="fas fa-exclamation-triangle"></i> This will actually send PurchaseGacha requests to the game server. Use at your own risk.</p>
                </div>

                <div id="panelDebug" class="panel hidden">
                    <div class="bg-gray-900 rounded-lg p-3">
                        <div class="flex justify-between items-center mb-2">
                            <span class="text-white font-mono text-sm"><i class="fas fa-terminal"></i> Live Debug Log</span>
                            <button id="clearDebug" class="text-gray-400 hover:text-white text-sm">Clear</button>
                        </div>
                        <div id="debugLog" class="debug-log"></div>
                    </div>
                </div>

                <div id="resultArea" class="mt-8 hidden">
                    <div class="border-t pt-4">
                        <h2 class="text-xl font-bold mb-3 flex items-center gap-2"><i class="fas fa-chart-line"></i> Results</h2>
                        <div id="resultContent" class="overflow-x-auto"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentJwt = '';
        const debugLogDiv = document.getElementById('debugLog');
        
        function addDebug(msg, type='info') {
            const time = new Date().toLocaleTimeString();
            const colors = { info: '#a0a0ff', error: '#ff8888', success: '#88ff88', warning: '#ffaa44' };
            const color = colors[type] || '#f0f0f0';
            const line = document.createElement('div');
            line.innerHTML = `<span style="color:#aaa;">[${time}]</span> <span style="color:${color};">${msg}</span>`;
            debugLogDiv.appendChild(line);
            debugLogDiv.scrollTop = debugLogDiv.scrollHeight;
        }

        function showLoading(btnId, loading=true) {
            const btn = document.getElementById(btnId);
            if(loading) {
                btn.disabled = true;
                btn.innerHTML = '<span class="spinner"></span> Loading...';
            } else {
                btn.disabled = false;
                if(btnId === 'btnGenerate') btn.innerHTML = '<i class="fas fa-key"></i> Generate Encrypted Payloads';
                else btn.innerHTML = '<i class="fas fa-dice-d6"></i> Perform Spins (WARNING: consumes spins!)';
            }
        }

        async function callAPI(endpoint, jwt) {
            addDebug(`Calling ${endpoint} with JWT (length ${jwt.length})`, 'info');
            const url = `/${endpoint}?jwt=${encodeURIComponent(jwt)}`;
            try {
                const response = await fetch(url, { method: 'POST', headers: { 'Accept': 'application/json' } });
                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.detail || `HTTP ${response.status}`);
                }
                addDebug(`[OK] ${endpoint} succeeded`, 'success');
                return { success: true, data };
            } catch (err) {
                addDebug(`[FAIL] ${endpoint} failed: ${err.message}`, 'error');
                return { success: false, error: err.message };
            }
        }

        async function generatePayloads() {
            const jwt = document.getElementById('jwt').value.trim();
            if (!jwt) { alert('Please enter JWT token'); return; }
            currentJwt = jwt;
            showLoading('btnGenerate', true);
            document.getElementById('resultArea').classList.remove('hidden');
            document.getElementById('resultContent').innerHTML = '<div class="text-center py-8"><span class="spinner"></span> Generating payloads...</div>';
            const res = await callAPI('generate', jwt);
            if (res.success) {
                displayGenerateResults(res.data);
                addDebug(`Generated ${res.data.events.length} events`, 'success');
            } else {
                document.getElementById('resultContent').innerHTML = `<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">Error: ${res.error}</div>`;
            }
            showLoading('btnGenerate', false);
        }

        async function spinEvents() {
            const jwt = document.getElementById('jwt').value.trim();
            if (!jwt) { alert('Please enter JWT token'); return; }
            if (!confirm('WARNING: This will actually use your spins! Are you 100% sure?')) return;
            currentJwt = jwt;
            showLoading('btnSpin', true);
            document.getElementById('resultArea').classList.remove('hidden');
            document.getElementById('resultContent').innerHTML = '<div class="text-center py-8"><span class="spinner"></span> Sending spin requests... (this may take a moment)</div>';
            const res = await callAPI('spin', jwt);
            if (res.success) {
                displaySpinResults(res.data);
                addDebug(`Spin test completed. Free events: ${res.data.filter(e=>e.is_free).length}/${res.data.length}`, 'success');
            } else {
                document.getElementById('resultContent').innerHTML = `<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">Error: ${res.error}</div>`;
            }
            showLoading('btnSpin', false);
        }

        function displayGenerateResults(data) {
            let html = `<p class="mb-2"><strong>Region:</strong> ${data.region}</p>`;
            html += `<div class="overflow-x-auto"><table class="min-w-full bg-white border border-gray-200 rounded-lg">
                <thead class="bg-gray-100"><tr>
                    <th class="px-4 py-2 border">Event ID</th><th class="px-4 py-2 border">Event Name</th><th class="px-4 py-2 border">Encrypted Payload (hex)</th><th class="px-4 py-2 border">Rare Items (Top 3)</th>
                </tr></thead><tbody>`;
            for (const ev of data.events) {
                html += `<tr class="border-b">
                    <td class="px-4 py-2">${ev.event_id}</td>
                    <td class="px-4 py-2">${escapeHtml(ev.event_name)}</td>
                    <td class="px-4 py-2"><code class="text-xs bg-gray-100 p-1 rounded block break-all">${ev.encrypted_hex}</code><button onclick="copyToClipboard('${ev.encrypted_hex}')" class="text-blue-500 text-xs mt-1"><i class="far fa-copy"></i> Copy</button></td>
                    <td class="px-4 py-2">${ev.rare_items.map(i=>escapeHtml(i)).join('<br>')}</td>
                </tr>`;
            }
            html += `</tbody></table></div>`;
            document.getElementById('resultContent').innerHTML = html;
        }

        function displaySpinResults(data) {
            let html = `<div class="overflow-x-auto"><table class="min-w-full bg-white border border-gray-200 rounded-lg">
                <thead class="bg-gray-100"><tr>
                    <th class="px-4 py-2 border">Event ID</th><th class="px-4 py-2 border">Event Name</th><th class="px-4 py-2 border">HTTP Status</th><th class="px-4 py-2 border">Result</th><th class="px-4 py-2 border">Encrypted Payload</th>
                </tr></thead><tbody>`;
            for (const ev of data) {
                const statusClass = ev.is_free ? 'text-green-600 font-bold' : 'text-red-600 font-bold';
                const statusText = ev.is_free ? 'FREE SPIN' : `PAID (${ev.status_code})`;
                html += `<tr class="border-b">
                    <td class="px-4 py-2">${ev.event_id}</td>
                    <td class="px-4 py-2">${escapeHtml(ev.event_name)}</td>
                    <td class="px-4 py-2">${ev.status_code}</td>
                    <td class="px-4 py-2 ${statusClass}">${statusText}</td>
                    <td class="px-4 py-2"><code class="text-xs bg-gray-100 p-1 rounded block break-all">${ev.encrypted_hex}</code><button onclick="copyToClipboard('${ev.encrypted_hex}')" class="text-blue-500 text-xs mt-1"><i class="far fa-copy"></i> Copy</button></td>
                </tr>`;
            }
            html += `</tbody></table></div>`;
            document.getElementById('resultContent').innerHTML = html;
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                addDebug('Copied to clipboard', 'success');
            }).catch(() => alert('Failed to copy'));
        }

        function escapeHtml(str) {
            return str.replace(/[&<>]/g, function(m) {
                if(m === '&') return '&amp;';
                if(m === '<') return '&lt;';
                if(m === '>') return '&gt;';
                return m;
            });
        }

        // Tab switching
        const tabs = ['Generate', 'Spin', 'Debug'];
        function activateTab(tab) {
            document.querySelectorAll('.panel').forEach(p => p.classList.add('hidden'));
            document.getElementById(`panel${tab}`).classList.remove('hidden');
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('tab-active', 'text-blue-600'));
            const activeBtn = tab === 'Generate' ? document.getElementById('tabGenerate') : (tab === 'Spin' ? document.getElementById('tabSpin') : document.getElementById('tabDebug'));
            activeBtn.classList.add('tab-active', 'text-blue-600');
        }
        document.getElementById('tabGenerate').onclick = () => activateTab('Generate');
        document.getElementById('tabSpin').onclick = () => activateTab('Spin');
        document.getElementById('tabDebug').onclick = () => activateTab('Debug');
        document.getElementById('btnGenerate').onclick = generatePayloads;
        document.getElementById('btnSpin').onclick = spinEvents;
        document.getElementById('clearDebug').onclick = () => { debugLogDiv.innerHTML = ''; addDebug('Debug log cleared', 'info'); };
        
        addDebug('Ready. Enter JWT and choose an action.', 'success');
    </script>
</body>
</html>
    """
    # Sanitize the HTML to remove any invalid surrogate characters
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
