import os
import json
import base64
import binascii
import gzip
import zlib
import threading
import time
import requests as http_requests
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from Crypto.Cipher import AES

app = FastAPI(title="Free Fire Gacha Payload Generator")

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
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    for host in hosts:
        url = f"https://{host}{endpoint}"
        headers_copy = headers.copy()
        headers_copy["Host"] = host
        headers_copy["Content-Length"] = str(len(body_bytes))
        try:
            resp = http_requests.post(url, headers=headers_copy, data=body_bytes,
                                      timeout=10, verify=False)
            raw = decompress_response(resp)
            decoded = decode_protobuf(raw) if resp.status_code == 200 else None
            return resp.status_code, decoded, raw
        except Exception:
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

@app.get("/")
async def root():
    return {"message": "Free Fire Gacha Payload Generator API. Use POST /generate?jwt=<your_token>"}

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

@app.on_event("startup")
def startup():
    load_item_database()
    thread = threading.Thread(target=self_pinger, daemon=True)
    thread.start()