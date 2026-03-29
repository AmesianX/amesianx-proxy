# Amesianx Proxy

<details>
<summary><b>English</b></summary>

## Overview

**Amesianx Proxy** is a general-purpose intercepting proxy designed for security testing. It sits between your traffic capture tool (e.g., Fiddler) and your editing proxy (e.g., Burp Suite), automatically transforming binary/encoded protocols into human-readable formats for easy inspection and modification.

### Key Features

- **Plugin-based architecture** — Automatically detects and transforms protocol-specific payloads
- **Bidirectional transformation** — Binary → readable on the way in, readable → binary on the way out
- **Dual TLS/HTTP support** — Single outbound port handles both encrypted and plain connections
- **Two editions** — Single-file (`amesianx_proxy.py`) and modular package (`amesianx/`)

### Included Plugins

| Plugin | Inbound (to Burp) | Outbound (to Server) |
|--------|-------------------|---------------------|
| **NexacroSSV** | SSV binary → XML | XML → SSV binary |
| **AMF** | AMF binary → JSON | JSON → AMF binary |

---

## How It Works

### Proxy Chain Architecture

```
┌─────────┐    ┌─────────┐    ┌──────────────┐    ┌──────┐    ┌──────────────┐    ┌────────┐
│ Browser  │───>│ Fiddler  │───>│ Proxy-IN     │───>│ Burp │───>│ Proxy-OUT    │───>│ Target │
│          │<───│ (8888)   │<───│ (8089)       │<───│(8080)│<───│ (8099)       │<───│ Server │
└─────────┘    └─────────┘    │ decode/encode │    │ edit │    │ encode/decode │    └────────┘
                               └──────────────┘    └──────┘    └──────────────┘
```

#### Request Flow (Browser → Server)

1. **Browser** sends request through **Fiddler** (traffic capture/logging)
2. **Fiddler** forwards to **Proxy-IN** (port 8089)
3. **Proxy-IN** detects protocol → transforms binary to readable format (SSV→XML, AMF→JSON)
4. Transformed request forwarded to **Burp Suite** (port 8080) for manual inspection/editing
5. **Burp** forwards edited request to **Proxy-OUT** (port 8099)
6. **Proxy-OUT** transforms readable format back to binary (XML→SSV, JSON→AMF)
7. Request sent to the **Target Server**

#### Response Flow (Server → Browser)

1. **Target Server** responds to **Proxy-OUT**
2. **Proxy-OUT** decodes response (binary → readable) so you can view it in Burp
3. **Burp** displays the decoded response
4. **Proxy-IN** encodes response back to original format (readable → binary)
5. Response returned to **Fiddler** → **Browser**

> **Non-matched requests** (protocols not handled by any plugin) pass through as-is without transformation.

---

## Setup Guide

### Prerequisites

- Python 3.6+
- Fiddler Classic (or any upstream traffic capture proxy)
- Burp Suite (Community or Pro)

### Step 1: Configure Fiddler

Fiddler acts as the first hop — it captures all browser traffic and forwards it to Proxy-IN.

1. Open **Fiddler** → **Tools** → **Options** → **Gateway**
2. Select **Manual Proxy**
3. Set proxy to: `127.0.0.1:8089`
4. Click **OK**

```
┌─────────────────────────────────────┐
│ Fiddler Gateway Settings            │
│                                     │
│ (●) Manual Proxy                    │
│     Address: 127.0.0.1              │
│     Port:    8089                   │
└─────────────────────────────────────┘
```

> This tells Fiddler to forward all traffic to Amesianx Proxy-IN instead of sending it directly to the internet.

### Step 2: Configure Burp Suite

Burp receives transformed (readable) traffic from Proxy-IN and sends it to Proxy-OUT after editing.

#### 2a. Proxy Listener

1. **Proxy** → **Proxy settings** → **Proxy listeners**
2. Ensure a listener is running on `127.0.0.1:8080`

#### 2b. Upstream Proxy (Critical)

This tells Burp to send outgoing traffic to Proxy-OUT instead of directly to the target:

1. **Settings** → **Network** → **Connections** → **Upstream proxy servers**
2. Add a rule:

| Field | Value |
|-------|-------|
| Destination host | `*` |
| Proxy host | `127.0.0.1` |
| Proxy port | `8099` |

```
┌─────────────────────────────────────┐
│ Burp Upstream Proxy                 │
│                                     │
│ Destination: *                      │
│ Proxy host:  127.0.0.1              │
│ Proxy port:  8099                   │
└─────────────────────────────────────┘
```

> Without this upstream proxy setting, Burp will send traffic directly to the target, bypassing the reverse transformation.

### Step 3: Start Amesianx Proxy

```bash
# Modular version
python -m amesianx

# Or single-file version
python amesianx_proxy.py
```

### Step 4: Verify the Chain

1. Open your browser (configured to use Fiddler at port 8888)
2. Navigate to a target application
3. You should see:
   - **Fiddler**: Raw traffic (original format)
   - **Burp**: Transformed traffic (XML/JSON — human-readable)
4. Edit the request in Burp → Forward → the proxy restores the original binary format automatically

---

## Usage

### Basic Usage

```bash
# Start with all plugins enabled (default)
python -m amesianx

# Single-file version (identical functionality)
python amesianx_proxy.py
```

### Command-Line Options

#### Port Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--listen-in PORT` | 8089 | Inbound port (Fiddler → Proxy) |
| `--listen-out PORT` | 8099 | Outbound port (Burp → Proxy) |
| `--burp PORT` | 8080 | Burp Suite proxy listener port |
| `--upstream PORT` | *(none)* | Upstream proxy for outbound (e.g., Fiddler 8888 for full round-trip logging) |

```bash
# Custom ports
python -m amesianx --listen-in 9001 --listen-out 9002 --burp 9090

# Route outbound traffic back through Fiddler for response logging
python -m amesianx --upstream 8888
```

#### Plugin Control

| Option | Description |
|--------|-------------|
| `--no-nexacro` | Disable NexacroSSV plugin (SSV ↔ XML) |
| `--no-amf` | Disable AMF plugin (AMF ↔ JSON) |
| `--raw-response` | Don't decode responses (show raw binary in Burp) |

```bash
# AMF only (disable Nexacro)
python -m amesianx --no-nexacro

# Nexacro only (disable AMF)
python -m amesianx --no-amf

# Don't transform responses — useful when you only need to edit requests
python -m amesianx --raw-response
```

#### Certificate Options

The outbound proxy (port 8099) uses TLS to handle HTTPS traffic from Burp. A self-signed certificate is used.

| Option | Description |
|--------|-------------|
| `--gen-cert` | Generate a fresh certificate using OpenSSL CLI (instead of embedded cert) |

```bash
# Use embedded certificate (default — no openssl required)
python -m amesianx

# Generate fresh certificate via openssl
python -m amesianx --gen-cert
```

### AMF CLI Decoder (Single-file version only)

The single-file version (`amesianx_proxy.py`) includes a standalone AMF analysis tool:

```bash
# Decode AMF file and show structure
python amesianx_proxy.py --amf-decode response.json

# Show data records as a table
python amesianx_proxy.py --amf-decode response.json --list

# Limit table rows
python amesianx_proxy.py --amf-decode response.json --list --limit 20

# Search/filter rows
python amesianx_proxy.py --amf-decode response.json --list --search "admin"

# Deep parse raw binary fields
python amesianx_proxy.py --amf-decode response.json --deep

# Full JSON dump
python amesianx_proxy.py --amf-decode response.json --json-dump
```

| Option | Description |
|--------|-------------|
| `--amf-decode FILE` | Decode an AMF response file (JSON or hex dump) |
| `--list` | Display data records as formatted table |
| `--limit N` | Max rows to display (default: 50) |
| `--search TEXT` | Filter rows containing text (case-insensitive) |
| `--deep` | Deep parse `__raw_b64` fields (BlazeDS tail-scanning) |
| `--json-dump` | Output full decoded JSON envelope |

---

## Plugin System

### How Plugins Work

Plugins are auto-discovered from the `plugins/` directory. Each plugin implements:

- **Detection** — `should_transform_inbound()` / `should_transform_outbound()` — checks if the payload matches this plugin's protocol
- **Transform** — `transform_inbound()` / `transform_outbound()` — converts between wire format and editable format
- **Response handling** — `transform_response_decode()` / `transform_response_encode()` — same for responses

First matching plugin wins. Non-matched traffic passes through unchanged.

### Writing Custom Plugins

Create a new `.py` file in `amesianx/plugins/`:

```python
from .base import BodyTransformPlugin

class MyPlugin(BodyTransformPlugin):
    name = "MyProtocol"

    def should_transform_inbound(self, body, headers):
        # Return True if this plugin should handle this request
        return b'MY_MAGIC_HEADER' in body

    def transform_inbound(self, body, headers):
        # Convert wire format → human-readable
        readable = my_decode(body)
        extra_headers = {"X-MyPlugin": "decoded"}
        return readable, extra_headers

    def should_transform_outbound(self, body, headers):
        return 'x-myplugin' in {k.lower(): v for k, v in headers.items()}

    def transform_outbound(self, body, headers):
        # Convert human-readable → wire format
        wire = my_encode(body)
        return wire, {}
```

The plugin will be automatically discovered and loaded on startup.

---

## Examples

### Example 1: Basic Nexacro SSV Interception

```bash
python -m amesianx --no-amf
```

**In Burp, you'll see XML instead of binary SSV:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Root xmlns="http://www.nexacroplatform.com/platform/dataset">
  <Parameters>
    <Parameter id="token">abc123</Parameter>
  </Parameters>
  <Dataset id="DS_INPUT">
    <ColumnInfo>
      <Column id="name" type="STRING" size="256" />
      <Column id="value" type="STRING" size="256" />
    </ColumnInfo>
    <Rows>
      <Row type="N">
        <Col id="name">param1</Col>
        <Col id="value">hello</Col>
      </Row>
    </Rows>
  </Dataset>
</Root>
```

Edit the XML in Burp, forward it, and the proxy converts it back to SSV binary automatically.

### Example 2: AMF/BlazeDS Interception

```bash
python -m amesianx --no-nexacro
```

**In Burp, you'll see JSON instead of AMF binary:**
```json
{
  "amf_version": 3,
  "headers": [],
  "bodies": [
    {
      "target": "null",
      "response": "/1",
      "value": {
        "__amf_type": "object",
        "__class": "flex.messaging.messages.RemotingMessage",
        "operation": "getData",
        "destination": "myService",
        "body": ["param1", "param2"]
      }
    }
  ]
}
```

Edit the JSON in Burp, forward it, and the proxy converts it back to AMF binary automatically.

---

## Architecture

```
amesianx/
├── __init__.py
├── __main__.py          # CLI entry point
├── run.py               # Convenience launcher
├── core/
│   ├── __init__.py
│   ├── certs.py         # TLS certificate management
│   ├── proxy.py         # Inbound/Outbound HTTP handlers
│   └── server.py        # Dual-stack (TLS + plain) HTTP server
└── plugins/
    ├── __init__.py      # Plugin auto-discovery
    ├── base.py          # BodyTransformPlugin base class
    ├── amf.py           # AMF binary ↔ JSON
    └── nexacro_ssv.py   # Nexacro SSV ↔ XML
```

---

## License

MIT License

</details>

<details open>
<summary><b>한국어</b></summary>

## 개요

**Amesianx Proxy**는 보안 테스트를 위한 범용 인터셉팅 프록시입니다. 트래픽 캡처 도구(예: Fiddler)와 편집용 프록시(예: Burp Suite) 사이에 위치하여, 바이너리/인코딩된 프로토콜을 자동으로 사람이 읽을 수 있는 형식으로 변환합니다.

### 주요 기능

- **플러그인 기반 아키텍처** — 프로토콜별 페이로드를 자동 감지하고 변환
- **양방향 변환** — 들어올 때 바이너리 → 읽기 가능, 나갈 때 읽기 가능 → 바이너리
- **TLS/HTTP 듀얼 지원** — 단일 아웃바운드 포트에서 암호화/평문 연결 모두 처리
- **두 가지 에디션** — 단일 파일(`amesianx_proxy.py`)과 모듈형 패키지(`amesianx/`)

### 포함된 플러그인

| 플러그인 | 인바운드 (Burp로) | 아웃바운드 (서버로) |
|----------|-------------------|---------------------|
| **NexacroSSV** | SSV 바이너리 → XML | XML → SSV 바이너리 |
| **AMF** | AMF 바이너리 → JSON | JSON → AMF 바이너리 |

---

## 동작 원리

### 프록시 체인 구조

```
┌─────────┐    ┌─────────┐    ┌──────────────┐    ┌──────┐    ┌──────────────┐    ┌────────┐
│ 브라우저  │───>│ Fiddler  │───>│ Proxy-IN     │───>│ Burp │───>│ Proxy-OUT    │───>│ 대상   │
│          │<───│ (8888)   │<───│ (8089)       │<───│(8080)│<───│ (8099)       │<───│ 서버   │
└─────────┘    └─────────┘    │ 디코드/인코드  │    │ 편집 │    │ 인코드/디코드 │    └────────┘
                               └──────────────┘    └──────┘    └──────────────┘
```

#### 요청 흐름 (브라우저 → 서버)

1. **브라우저**가 **Fiddler** (포트 8888)를 통해 요청 전송
2. **Fiddler**가 **Proxy-IN** (포트 8089)으로 전달
3. **Proxy-IN**이 프로토콜 감지 → 바이너리를 읽기 가능한 형식으로 변환 (SSV→XML, AMF→JSON)
4. 변환된 요청이 **Burp Suite** (포트 8080)으로 전달 → 수동 검사/편집
5. **Burp**가 편집된 요청을 **Proxy-OUT** (포트 8099)으로 전달
6. **Proxy-OUT**이 읽기 가능한 형식을 다시 바이너리로 변환 (XML→SSV, JSON→AMF)
7. 원본 형식으로 **대상 서버**에 전송

#### 응답 흐름 (서버 → 브라우저)

1. **대상 서버**가 **Proxy-OUT**에 응답
2. **Proxy-OUT**이 응답을 디코딩 (바이너리 → 읽기 가능) → Burp에서 확인 가능
3. **Burp**가 디코딩된 응답을 표시
4. **Proxy-IN**이 응답을 다시 원본 형식으로 인코딩 (읽기 가능 → 바이너리)
5. **Fiddler** → **브라우저**로 응답 반환

> **매칭되지 않는 요청** (플러그인이 처리하지 않는 프로토콜)은 변환 없이 그대로 통과합니다.

---

## 설정 가이드

### 사전 요구사항

- Python 3.6+
- Fiddler Classic (또는 다른 트래픽 캡처 프록시)
- Burp Suite (Community 또는 Pro)

### Step 1: Fiddler 설정

Fiddler는 첫 번째 홉입니다 — 모든 브라우저 트래픽을 캡처하여 Proxy-IN으로 전달합니다.

1. **Fiddler** 열기 → **Tools** → **Options** → **Gateway**
2. **Manual Proxy** 선택
3. 프록시 설정: `127.0.0.1:8089`
4. **OK** 클릭

```
┌─────────────────────────────────────┐
│ Fiddler Gateway 설정                 │
│                                     │
│ (●) Manual Proxy                    │
│     Address: 127.0.0.1              │
│     Port:    8089                   │
└─────────────────────────────────────┘
```

> Fiddler가 트래픽을 인터넷으로 직접 보내지 않고 Amesianx Proxy-IN으로 전달하도록 합니다.

### Step 2: Burp Suite 설정

Burp는 Proxy-IN에서 변환된(읽기 가능한) 트래픽을 받고, 편집 후 Proxy-OUT으로 전송합니다.

#### 2a. Proxy Listener

1. **Proxy** → **Proxy settings** → **Proxy listeners**
2. `127.0.0.1:8080`에서 리스너가 실행 중인지 확인

#### 2b. Upstream Proxy (중요!)

Burp가 나가는 트래픽을 대상 서버로 직접 보내지 않고 Proxy-OUT으로 보내도록 설정합니다:

1. **Settings** → **Network** → **Connections** → **Upstream proxy servers**
2. 규칙 추가:

| 필드 | 값 |
|------|-----|
| Destination host | `*` |
| Proxy host | `127.0.0.1` |
| Proxy port | `8099` |

```
┌─────────────────────────────────────┐
│ Burp Upstream Proxy 설정             │
│                                     │
│ Destination: *                      │
│ Proxy host:  127.0.0.1              │
│ Proxy port:  8099                   │
└─────────────────────────────────────┘
```

> 이 Upstream Proxy 설정이 없으면 Burp가 트래픽을 대상 서버로 직접 전송하여 역변환이 수행되지 않습니다.

### Step 3: Amesianx Proxy 시작

```bash
# 모듈형 버전
python -m amesianx

# 또는 단일 파일 버전
python amesianx_proxy.py
```

### Step 4: 체인 확인

1. 브라우저 열기 (Fiddler 포트 8888 사용 설정)
2. 대상 애플리케이션으로 이동
3. 확인할 내용:
   - **Fiddler**: 원본 트래픽 (바이너리 형식)
   - **Burp**: 변환된 트래픽 (XML/JSON — 사람이 읽을 수 있는 형식)
4. Burp에서 요청 편집 → Forward → 프록시가 자동으로 원본 바이너리 형식으로 복원

---

## 사용법

### 기본 사용

```bash
# 모든 플러그인 활성화 (기본값)
python -m amesianx

# 단일 파일 버전 (동일한 기능)
python amesianx_proxy.py
```

### 명령줄 옵션

#### 포트 설정

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--listen-in PORT` | 8089 | 인바운드 포트 (Fiddler → Proxy) |
| `--listen-out PORT` | 8099 | 아웃바운드 포트 (Burp → Proxy) |
| `--burp PORT` | 8080 | Burp Suite 프록시 리스너 포트 |
| `--upstream PORT` | *(없음)* | 아웃바운드용 업스트림 프록시 (예: Fiddler 8888로 응답도 로깅) |

```bash
# 커스텀 포트
python -m amesianx --listen-in 9001 --listen-out 9002 --burp 9090

# 아웃바운드 트래픽을 Fiddler를 통해 라우팅 (응답 로깅용)
python -m amesianx --upstream 8888
```

#### 플러그인 제어

| 옵션 | 설명 |
|------|------|
| `--no-nexacro` | NexacroSSV 플러그인 비활성화 (SSV ↔ XML) |
| `--no-amf` | AMF 플러그인 비활성화 (AMF ↔ JSON) |
| `--raw-response` | 응답을 디코딩하지 않음 (Burp에서 원본 바이너리 표시) |

```bash
# AMF만 사용 (Nexacro 비활성화)
python -m amesianx --no-nexacro

# Nexacro만 사용 (AMF 비활성화)
python -m amesianx --no-amf

# 응답 변환 안 함 — 요청만 편집할 때 유용
python -m amesianx --raw-response
```

#### 인증서 옵션

아웃바운드 프록시(포트 8099)는 Burp의 HTTPS 트래픽을 처리하기 위해 TLS를 사용합니다. 자체 서명 인증서를 사용합니다.

| 옵션 | 설명 |
|------|------|
| `--gen-cert` | OpenSSL CLI로 새 인증서 생성 (내장 인증서 대신) |

```bash
# 내장 인증서 사용 (기본값 — openssl 불필요)
python -m amesianx

# openssl로 새 인증서 생성
python -m amesianx --gen-cert
```

### AMF CLI 디코더 (단일 파일 버전 전용)

단일 파일 버전(`amesianx_proxy.py`)에는 독립형 AMF 분석 도구가 포함되어 있습니다:

```bash
# AMF 파일 디코드 및 구조 표시
python amesianx_proxy.py --amf-decode response.json

# 데이터 레코드를 테이블로 표시
python amesianx_proxy.py --amf-decode response.json --list

# 테이블 행 수 제한
python amesianx_proxy.py --amf-decode response.json --list --limit 20

# 행 검색/필터링
python amesianx_proxy.py --amf-decode response.json --list --search "admin"

# raw 바이너리 필드 심층 파싱
python amesianx_proxy.py --amf-decode response.json --deep

# 전체 JSON 덤프
python amesianx_proxy.py --amf-decode response.json --json-dump
```

| 옵션 | 설명 |
|------|------|
| `--amf-decode FILE` | AMF 응답 파일 디코드 (JSON 또는 hex 덤프) |
| `--list` | 데이터 레코드를 포맷된 테이블로 표시 |
| `--limit N` | 최대 표시 행 수 (기본: 50) |
| `--search TEXT` | 텍스트를 포함하는 행 필터링 (대소문자 무시) |
| `--deep` | `__raw_b64` 필드 심층 파싱 (BlazeDS tail-scanning) |
| `--json-dump` | 전체 디코딩된 JSON envelope 출력 |

---

## 플러그인 시스템

### 플러그인 동작 방식

플러그인은 `plugins/` 디렉토리에서 자동 검색됩니다. 각 플러그인이 구현하는 메서드:

- **감지** — `should_transform_inbound()` / `should_transform_outbound()` — 페이로드가 이 플러그인의 프로토콜과 일치하는지 확인
- **변환** — `transform_inbound()` / `transform_outbound()` — 와이어 형식과 편집 가능한 형식 간 변환
- **응답 처리** — `transform_response_decode()` / `transform_response_encode()` — 응답에 대해 동일한 작업 수행

첫 번째로 매칭되는 플러그인이 처리합니다. 매칭되지 않는 트래픽은 변경 없이 통과합니다.

### 커스텀 플러그인 작성

`amesianx/plugins/`에 새 `.py` 파일을 생성합니다:

```python
from .base import BodyTransformPlugin

class MyPlugin(BodyTransformPlugin):
    name = "MyProtocol"

    def should_transform_inbound(self, body, headers):
        # 이 플러그인이 이 요청을 처리해야 하면 True 반환
        return b'MY_MAGIC_HEADER' in body

    def transform_inbound(self, body, headers):
        # 와이어 형식 → 사람이 읽을 수 있는 형식
        readable = my_decode(body)
        extra_headers = {"X-MyPlugin": "decoded"}
        return readable, extra_headers

    def should_transform_outbound(self, body, headers):
        return 'x-myplugin' in {k.lower(): v for k, v in headers.items()}

    def transform_outbound(self, body, headers):
        # 사람이 읽을 수 있는 형식 → 와이어 형식
        wire = my_encode(body)
        return wire, {}
```

플러그인은 시작 시 자동으로 검색되어 로드됩니다.

---

## 사용 예시

### 예시 1: Nexacro SSV 인터셉트

```bash
python -m amesianx --no-amf
```

**Burp에서 바이너리 SSV 대신 XML로 표시됩니다:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Root xmlns="http://www.nexacroplatform.com/platform/dataset">
  <Parameters>
    <Parameter id="token">abc123</Parameter>
  </Parameters>
  <Dataset id="DS_INPUT">
    <ColumnInfo>
      <Column id="name" type="STRING" size="256" />
      <Column id="value" type="STRING" size="256" />
    </ColumnInfo>
    <Rows>
      <Row type="N">
        <Col id="name">param1</Col>
        <Col id="value">hello</Col>
      </Row>
    </Rows>
  </Dataset>
</Root>
```

Burp에서 XML을 편집하고 Forward하면 프록시가 자동으로 SSV 바이너리로 변환합니다.

### 예시 2: AMF/BlazeDS 인터셉트

```bash
python -m amesianx --no-nexacro
```

**Burp에서 AMF 바이너리 대신 JSON으로 표시됩니다:**
```json
{
  "amf_version": 3,
  "headers": [],
  "bodies": [
    {
      "target": "null",
      "response": "/1",
      "value": {
        "__amf_type": "object",
        "__class": "flex.messaging.messages.RemotingMessage",
        "operation": "getData",
        "destination": "myService",
        "body": ["param1", "param2"]
      }
    }
  ]
}
```

Burp에서 JSON을 편집하고 Forward하면 프록시가 자동으로 AMF 바이너리로 변환합니다.

---

## 프로젝트 구조

```
amesianx-proxy/
├── amesianx_proxy.py        # 단일 파일 버전 (독립 실행)
└── amesianx/                # 모듈형 버전
    ├── __init__.py
    ├── __main__.py           # CLI 진입점
    ├── run.py                # 편의 런처
    ├── core/
    │   ├── __init__.py
    │   ├── certs.py          # TLS 인증서 관리
    │   ├── proxy.py          # 인바운드/아웃바운드 HTTP 핸들러
    │   └── server.py         # 듀얼 스택 (TLS + 평문) HTTP 서버
    └── plugins/
        ├── __init__.py       # 플러그인 자동 검색
        ├── base.py           # BodyTransformPlugin 베이스 클래스
        ├── amf.py            # AMF 바이너리 ↔ JSON
        └── nexacro_ssv.py    # Nexacro SSV ↔ XML
```

---

## 라이선스

MIT License

</details>
