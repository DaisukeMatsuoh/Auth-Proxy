# auth-proxy

既存のWebアプリやファイルに**認証を後付けする**ための、認証特化型プロキシサーバーです。

auth-proxyは認証処理を担い、認証済みリクエストのみ上流アプリに転送します。上流サービスはユーザー認証を一切実装することなく、`X-Auth-*` ヘッダーを読むだけでユーザーを識別することが出来ます。

## 動作モード

auth-proxyは二種類の使い方があります。

| モード | 環境変数 | 用途 | 推奨デプロイ |
|---|---|---|---|
| **静的ファイルモード** | `AUTH_PROXY_SERVE_PATH` のみ | 社内ドキュメント・写真など静的サイトのため認証機能。認証機能と静的サイトのホスティングの両方を担います。 | シングルバイナリ |
| **プロキシモード** | `AUTH_PROXY_UPSTREAM_APP_URL` のみ | 既存Webアプリ（静的ではない動的なアプリ）に認証機能だけ後でつけたい場合に利用します。auth-proxyの後ろにWebアプリが隠れるようにDockerを使う必要があります。 | Docker Compose |
| **併用モード** | 両方設定 | 静的ファイルモードとプロキシモードの両方とも利用することもできます。 | Docker Compose |

`AUTH_PROXY_SERVE_PATH` と `AUTH_PROXY_UPSTREAM_APP_URL` はいずれか一方または両方を設定してください。**両方未設定の場合は起動エラー**になります。

## oauth2-proxy との違い

| | auth-proxy | oauth2-proxy |
|---|---|---|
| ユーザー管理 | 内蔵しているSQLiteで実現（管理画面付き） | Google / GitHub等の外部IdPに依存 |
| セットアップ | バイナリ配置またはDocker Composeに追加 | OAuthアプリ登録・IdP設定が必要 |
| 静的ファイル配信 | ✅ 内蔵 | ❌ |
| MFA | ✅ TOTP（内蔵） | IdP依存 |
| 外部サービス不要 | ✅ | ❌ |
| イメージサイズ | 極小（静的バイナリ） | 中程度 |

---

## 目次

- [機能一覧](#機能一覧)
- [セキュリティ設計](#セキュリティ設計)
- [デプロイ: 静的ファイルモード](#デプロイ-静的ファイルモード)
- [デプロイ: プロキシモード (Docker)](#デプロイ-プロキシモード-docker)
- [環境変数リファレンス](#環境変数リファレンス)
- [CLIリファレンス](#cliリファレンス)
- [上流サービスへのヘッダー伝達](#上流サービスへのヘッダー伝達)
- [ゲストトークン機能](#ゲストトークン機能)
- [運用](#運用)
- [トラブルシューティング](#トラブルシューティング)
- [プロジェクト構成](#プロジェクト構成)

---

## 機能一覧

| フェーズ | 機能 | 状態 |
|---|---|---|
| Phase 1 | リバースプロキシ基盤・SQLiteセッション永続化 | ✅ 実装済み |
| Phase 2 | Web管理画面（ユーザー一覧・追加・編集・削除） | ✅ 実装済み |
| Phase 3a | MFA（TOTP・バックアップコード・デバイス記憶） | ✅ 実装済み |
| Phase 3a-2 | 管理者MFA強制無効化・ユーザーセキュリティ設定・パスワード変更 | ✅ 実装済み |
| Phase 4 | ゲストトークン機能（回数制限・パスワード付き共有リンク） | ✅ 実装済み |
| Phase Docker | Dockerfile・Compose例・動作モード検証 | ✅ 実装済み |
| Phase 3b | パスキー（WebAuthn） | 🔜 予定 |

---

## セキュリティ設計

### 静的ファイルモード

auth-proxyでHTTPリクエストを扱えます。`AUTH_PROXY_SERVE_PATH` 以下のファイルには承認されたユーザーのみ閲覧できるような制御をします。パストラバーサル（`../`等）は内部で防止しています。

### プロキシモード

プロキシモードではDockerを利用して、上流サービスと同じコンテナに入れ込みます。 上流アプリは`internal: true` ネットワークにのみ接続して上流アプリ自体はポートを公開しないのでDocker外から直接アクセスすることは出来ません。認証されたユーザーのみauth-proxyにより上流サービスにアクセスすることができます。

上流サービスはauth-proxyより `X-Auth-*` ヘッダーを受け取り、個々に書かれたユーザー情報でユーザーを判別できます。`X-Auth-*`ヘッダーはauth-proxy以外は書き込まないようにしているので、上流サービスはJWT署名検証などのセキュリティに関する実装をする必要がなく、判別されたユーザに対しての振る舞いに集中できます。

### Cookie属性

```
Set-Cookie: session_id=<token>; HttpOnly; Secure; SameSite=Strict; Max-Age=<TTL秒>
```

上記の属性はすべて必須です。`Secure` 属性があるため、TLSを終端するリバースプロキシ（Traefik等）と組み合わせることが前提としています。

### その他

- パスワード: Argon2id でハッシュ化。平文は一切保存・ログ出力しない。
- セッションID: `OsRng` で生成した16バイトのhex文字列（32文字）
- ブルートフォース対策: ログイン失敗時に500ms遅延
- X-Auth-* 偽装防止: 受信リクエストの `X-Auth-` ヘッダーは転送前に必ず除去



## デプロイ: 静的ファイルモード

社内ドキュメントや写真ギャラリーなど、**静的ファイルをホスティングした上で認証をつけたい**場合にはこちらでデプロイできます。

```
[ブラウザ]
    │ HTTPS
    ▼
[Traefik / nginx 等]  ← TLS終端
    │ HTTP (127.0.0.1)
    ▼
[auth-proxy バイナリ]  ← systemd で直接起動
    │
    ├── /login /logout /admin/*   auth-proxy が処理
    └── /*                        AUTH_PROXY_SERVE_PATH からファイルを返す
         └── SQLite (sessions, users)
```

### セットアップ手順

```bash
# 1. バイナリを配置
sudo cp target/release/auth-proxy /usr/local/bin/
sudo chmod +x /usr/local/bin/auth-proxy

# 2. ディレクトリと設定ファイルの作成
sudo mkdir -p /etc/auth-proxy /var/lib/auth-proxy
sudo cp .env.auth-proxy.example /etc/auth-proxy/.env
sudo chmod 600 /etc/auth-proxy/.env

# 3. .env を編集（AUTH_PROXY_SERVE_PATH, AUTH_PROXY_LISTEN_ADDR=127.0.0.1:8080 等を設定）
sudo vim /etc/auth-proxy/.env

# 4. 最初の管理者ユーザーを作成
sudo auth-proxy init-admin

# 5. systemd サービスを登録・起動
sudo cp systemd/auth-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable auth-proxy
sudo systemctl start auth-proxy
```

### systemd ユニットファイル例

systemdでデーモン化する場合の参考:

`/etc/systemd/system/auth-proxy.service`:

```ini
[Unit]
Description=Auth Proxy Server
After=network.target

[Service]
Type=simple
User=www-data
EnvironmentFile=/etc/auth-proxy/.env
ExecStart=/usr/local/bin/auth-proxy serve
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/auth-proxy
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### Traefik 設定例（静的ファイルモード）

```yaml
http:
  routers:
    my-docs:
      rule: "Host(`docs.example.com`)"
      entryPoints:
        - websecure
      tls: {}
      service: auth-proxy-svc
  services:
    auth-proxy-svc:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
```



## デプロイ: プロキシモード (Docker)

既存のWebアプリに認証を後付けしたい場合はこちらでデプロイ。上流サービスをDockerの内部ネットワークに閉じ込めることでネットワーク隔離を実現します。

```
[ブラウザ]
    │ HTTPS
    ▼
[Traefik / nginx 等]
    │ HTTP (127.0.0.1)
    ▼
[auth-proxy コンテナ]
    │
    ├── /login /logout /admin/*   auth-proxy が処理
    └── /*                        X-Auth-* ヘッダー付与 → 上流転送
         │ Docker 内部ネットワーク
         ▼
    [上流サービス コンテナ]  ← ホストにポートを公開しない
```

### Step 1: 自分のアプリをDockerイメージにする

プロキシモードは上流サービス（自分のアプリ）がDockerイメージになっている前提で設計されています。まずは自分のアプリをDockerイメージにしてみましょう。**アプリのコードは一切変更しなくて大丈夫です。**

変更しなくてもいい、と言いながらも、アプリのリッスンするポートとアドレスに関しては変更が必要かもしれません。**アドレスとポートの受付を `0.0.0.0`（全インターフェース）でリッスンさせてください。**`127.0.0.1` にバインドしているとコンテナ外（auth-proxy）からアクセスできなくなってしまいます。

Dockerイメージをつくるためには以下の様なdockerfileを作る必要があります。テキストエディタでdockerfileを下記の例を参考に作ります：

#### Python (Flask / FastAPI) の例

```dockerfile
# アプリのリポジトリに Dockerfile を追加する
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# 0.0.0.0 でリッスンさせること（127.0.0.1 はNG）
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3000"]
```

#### Go の例

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=0 で完全静的バイナリにする（scratch で動作させるために必須）
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o app .

FROM scratch
COPY --from=builder /build/app /app
ENTRYPOINT ["/app"]
```

```go
// main.go: ポートバインドは 0.0.0.0 で行うこと
http.ListenAndServe("0.0.0.0:3000", handler)
```

#### Rust の例

```dockerfile
FROM rust:1.77-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN rm -rf src
COPY . .
RUN touch src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/my-app /my-app
ENTRYPOINT ["/my-app"]
```

```rust
// main.rs: 0.0.0.0 でリッスンすること
let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
axum::serve(listener, app).await?;
```

auth-proxy自体もRustで書かれており、同じ `scratch` ベースのマルチステージビルドパターンを使っています。自分のアプリも同じ構成にすることでイメージサイズを最小化できます。

#### Node.js (Express) の例

```dockerfile
FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
CMD ["node", "server.js"]
```

```js
// server.js: host を省略すると 0.0.0.0 になる（Node.jsのデフォルト）
app.listen(3000);
```

#### 既存イメージ（変更なし）をそのまま使う場合

nginxやWordPress等、公式イメージがすでにあるアプリはDockerfileを書く必要がありません。そのままComposeに書けばOKです。

```yaml
# docker-compose.yml の app サービス部分
app:
  image: nginx:alpine          # 公式イメージをそのまま使う
  volumes:
    - ./html:/usr/share/nginx/html:ro
  # ports: は書かない（auth-proxyが中継するため不要）
```

---

#### Dockerfileって何？書いてはみたけど…

Dockerfileは「イメージの作り方のレシピ」です。これで上流サービスの作り方が整いました。auth-proxyのイメージと併せてあとで、一緒にビルドして、一つのDockerサービスとして纏めて動くようにします。

```
Dockerfile（レシピ）
    │
    │ docker build（料理する。あなたのアプリとauth-proxyを併せて一つのDockerイメージにします）
    ▼
Dockerイメージ（完成品。サーバー上に保存される）
    │
    │ docker compose up（実際に動かす）
    ▼
コンテナ（動いているプロセス）
```

#### ディレクトリ構成のイメージ

auth-proxy側のファイルと自分のアプリのファイルを同じ場所に置いて作業する感じです。

```
my-project/                     ← 作業ディレクトリ（任意の名前でOK）
├── docker-compose.yml          ← auth-proxyとアプリをまとめて管理するぞ、と言うレシピ。 (Step.2)
├── .env.auth-proxy             ← auth-proxy側の設定
│
└── my-app/                     ← 自分のアプリ(上流サービス)のリポジトリ
    ├── Dockerfile              ← Step 1 で作成したもの。自分のアプリのレシピ
    ├── main.py（またはmain.go等）
    └── ...
```

#### 

### Step 2: docker-compose.yml を作成する

```bash
cp docker-compose.example.yml docker-compose.yml
```

`docker-compose.yml` を編集して `app` サービスを自分のアプリに置き換える。**`app` サービスに `ports:` は書かないこと！**これがネットワーク隔離の核心。書いてしまうと、auth-proxy飛ばしてそのポートからサービスが見えてしまうので注意！

```yaml
services:
  auth-proxy:
    image: ghcr.io/your-org/auth-proxy:latest
    ports:
      - "127.0.0.1:${AUTH_PROXY_HOST_PORT:-8080}:8080"   # ホスト側ポート (環境変数で変更可)
    volumes:
      - auth-proxy-data:/var/lib/auth-proxy
    env_file:
      - .env.auth-proxy
    networks:
      - internal
    restart: unless-stopped
    depends_on:
      - app

  app:
    # ↓ 自分のアプリに応じていずれか1行を選ぶ（他の行はコメントアウトのままにする）
    build: ./my-app             # 【自作アプリ】./my-app/Dockerfile からビルドする
    # image: my-app:latest      # 【ビルド済み】すでにビルドしたイメージを使う
    # image: nginx:alpine       # 【公式イメージ】Dockerfileなしでそのまま使う
    # ports: は絶対に書かない ← ネットワーク隔離❗
    networks:
      - internal
    restart: unless-stopped

networks:
  internal:
    internal: true

volumes:
  auth-proxy-data:
```

`AUTH_PROXY_UPSTREAM_APP_URL` はComposeのサービス名（上記のdocker-compose.ymlを利用している場合は `app`）を使って指定します。

```dotenv
# .env.auth-proxy
AUTH_PROXY_UPSTREAM_APP_URL=http://app:3000   # "app" はComposeのサービス名、3000はアプリのポート
```

アプリが別のポートでリッスンしている場合（例: 8000番）はそこを変更してください。サービス名はdocker-compose.ymlの `services:` の下のキー名に合わせること！

**ホスト側のポートについて**: docker-compose.yml の `ports:` 設定では `${AUTH_PROXY_HOST_PORT:-8080}` を使用しており、デフォルトは 8080 です。別のポートを使う場合は以下のいずれかで変更できます：
- `export AUTH_PROXY_HOST_PORT=9000` の後に `docker compose up`
- または docker-compose.yml の `ports:` セクションを直接編集

---

### Step 3: 環境変数ファイルを作成する

```bash
cp .env.auth-proxy.example .env.auth-proxy
```

最低限以下を設定してください。どれもauth-proxyが参照します。

```dotenv
AUTH_PROXY_UPSTREAM_APP_URL=http://app:3000
AUTH_PROXY_DB_PATH=/var/lib/auth-proxy/auth-proxy.db
AUTH_PROXY_LISTEN_ADDR=0.0.0.0:8080   # コンテナ内のリッスンアドレス（固定値）
AUTH_PROXY_SESSION_TTL_HOURS=8
AUTH_PROXY_ISSUER_NAME=my-service
AUTH_PROXY_MFA_ENCRYPTION_KEY=xxx    # ← openssl rand -hex 32などで作成したランダムシードを記載
AUTH_PROXY_GUEST_TOKEN_SECRET=yyy    # ← openssl rand -hex 32などで作成したランダムシードを記載
AUTH_PROXY_GUEST_TOKEN_API_KEY=zzz   # ← openssl rand -hex 32などで作成したランダムシードを記載
```

**ポート設定について**:
- `AUTH_PROXY_LISTEN_ADDR=0.0.0.0:8080` はコンテナ内部のリッスンアドレスで固定（変更不要）
- ホスト側のポートは docker-compose.yml の `${AUTH_PROXY_HOST_PORT:-8080}` で制御（環境変数で変更可）

`AUTH_PROXY_MFA_ENCRYPTION_KEY` 等のシークレットは一度生成したら変更しないこと。変更するとMFAの再設定が必要になります。

---

### Step 4: Dockerイメージのビルド

いよいよ、dockerイメージの作成します。
先ほどの以下の様なフォルダ構成になっているとして、`my-project`ディレクトリに移動します。

```
my-project/                     ← 作業ディレクトリ（任意の名前でOK）
├── docker-compose.yml          ← auth-proxyとアプリをまとめて管理するぞ、と言うレシピ。 (Step.2)
├── .env.auth-proxy             ← auth-proxy側の設定
│
└── my-app/                     ← 自分のアプリ(上流サービス)のリポジトリ
    ├── Dockerfile              ← Step 1 で作成したもの。自分のアプリのレシピ
    ├── main.py（またはmain.go等）
    └── ...
```

以下のコマンドを実行してください。dockerのインストールが出来ていない場合は[公式ページ](https://docs.docker.com/engine/install/)よりインストールしてください。

```bash
docker compose build

# 実行例と出力イメージ:
# => [app builder 1/5] FROM golang:1.22-alpine   ← ベースイメージをダウンロード
# => [app builder 2/5] COPY go.mod go.sum ./      ← ファイルをコピー
# => [app builder 3/5] RUN go mod download         ← 依存をダウンロード
# => [app builder 4/5] RUN go build -o app .       ← コンパイル
# => [app] COPY --from=builder /build/app /app     ← 実行イメージに配置
# => exporting to image                             ← イメージ完成
```

無事にビルドが完了すると、イメージファイルがローカル環境に保存されます。以下のコマンドで確認してみてください：

```bash
docker images
# REPOSITORY         TAG       IMAGE ID       SIZE
# my-project-app     latest    abc123def456   8.2MB   ← 自分のアプリ
# auth-proxy         latest    xyz789ghi012   4.1MB   ← auth-proxy
```

##### コードを変更したときの再ビルド

アプリのコードを変更したら都度 `docker compose build` を再実行してイメージを更新し、コンテナを再起動します。（起動などは次のステップで説明します）

```bash
# コード変更後
docker compose build app        # appサービスだけビルドし直す
docker compose up -d app        # appコンテナだけ再起動する
```



### Step.5 初回起動と管理者ユーザー作成

それではauth-proxyと上流サービスを起動してみましょう。最初に管理者ユーザーを作ります。管理者は上流サービス（あなたのアプリ）にアクセス出来るユーザーを管理できます。

```bash
# アプリイメージのビルド（コード変更後は再度ビルドしてください）
docker compose build

# 管理者ユーザーを対話的に作成します（初回のみ行ってください）
docker compose run --rm auth-proxy init-admin

# 管理者ユーザーが出来れば後はバックグラウンドで起動します
docker compose up -d

# ログで正常起動を確認
docker compose logs -f auth-proxy
```

正常起動時のログ例:

```
auth-proxy  | INFO auth_proxy: listening on 0.0.0.0:8080
auth-proxy  | INFO auth_proxy: upstream: http://app:3000
auth-proxy  | INFO auth_proxy: mode: proxy
```



### Step 6: Traefik / nginx からルーティングする

auth-proxyのポート（`127.0.0.1:8080`）にTraefikまたはnginxから向けるように設定してください。以下は参考情報です:

**Traefik 設定例（ホスト直接で動かしている場合）**:

```yaml
http:
  routers:
    my-app:
      rule: "Host(`app.example.com`)"
      entryPoints:
        - websecure
      tls: {}
      service: auth-proxy-svc
  services:
    auth-proxy-svc:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
```

**nginx 設定例**:

```nginx
server {
    listen 443 ssl;
    server_name app.example.com;
    # ... TLS設定 ...

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```



## 環境変数リファレンス

| 変数 | 必須 | デフォルト | 説明 |
|---|---|---|---|
| `AUTH_PROXY_SERVE_PATH` | ※1 | — | 静的ファイルを配信するディレクトリパス |
| `AUTH_PROXY_UPSTREAM_APP_URL` | ※1 | — | 上流サービスの URL（例: `http://app:3000`） |
| `AUTH_PROXY_DB_PATH` | — | `auth_proxy.db` | SQLite データベースファイルパス |
| `AUTH_PROXY_LISTEN_ADDR` | — | `0.0.0.0:8080` | サーバーがリッスンするアドレス・ポート（コンテナ内部） |
| `AUTH_PROXY_SESSION_TTL_HOURS` | — | `8` | セッション有効期間（時間） |
| `AUTH_PROXY_ISSUER_NAME` | — | `auth-proxy` | `X-Auth-Issuer` ヘッダーの値 |
| `AUTH_PROXY_MFA_ENCRYPTION_KEY` | — | ※2 | TOTP シークレットの暗号化キー（hex 64文字） |
| `AUTH_PROXY_GUEST_TOKEN_SECRET` | — | ※2 | ゲストトークン署名キー（hex 64文字） |
| `AUTH_PROXY_GUEST_TOKEN_API_KEY` | — | ※2 | ゲストトークン発行 API の認証キー |
| `AUTH_PROXY_HOST_PORT` | — | `8080` | docker-compose ホスト側のバインドポート（環境変数） |
| `RUST_LOG` | — | `info` | ログレベル（`trace` / `debug` / `info` / `warn` / `error`） |

※1 `AUTH_PROXY_SERVE_PATH` と `AUTH_PROXY_UPSTREAM_APP_URL` はいずれか一方または両方を設定してください。両方未設定の場合は起動エラーになります。

※2 デフォルト値はあるが本番環境では必ず `openssl rand -hex 32` で生成した値を設定してください。

**ポート設定について**:
- **`AUTH_PROXY_LISTEN_ADDR`** (コンテナ内部):
  - シングルバイナリ（静的ファイルモード）: `.env` に `AUTH_PROXY_LISTEN_ADDR=127.0.0.1:8080` を明示
  - Docker モード: `0.0.0.0:8080` で固定（変更不要）
- **`AUTH_PROXY_HOST_PORT`** (ホスト側):
  - Docker Compose でのみ使用。環境変数で docker-compose.yml の `ports:` 設定を制御
  - 例: `AUTH_PROXY_HOST_PORT=9000 docker compose up` でホスト側のポートを 9000 に変更

### 設定例（静的ファイルモード）

```dotenv
AUTH_PROXY_SERVE_PATH=/var/www/html
AUTH_PROXY_DB_PATH=/var/lib/auth-proxy/auth-proxy.db
AUTH_PROXY_LISTEN_ADDR=127.0.0.1:8080
AUTH_PROXY_SESSION_TTL_HOURS=8
AUTH_PROXY_MFA_ENCRYPTION_KEY=<openssl rand -hex 32>
AUTH_PROXY_GUEST_TOKEN_SECRET=<openssl rand -hex 32>
AUTH_PROXY_GUEST_TOKEN_API_KEY=<openssl rand -hex 32>
RUST_LOG=info
```

### 設定例（プロキシモード / Docker）

```dotenv
AUTH_PROXY_UPSTREAM_APP_URL=http://app:3000
AUTH_PROXY_DB_PATH=/var/lib/auth-proxy/auth-proxy.db
AUTH_PROXY_LISTEN_ADDR=0.0.0.0:8080
AUTH_PROXY_SESSION_TTL_HOURS=8
AUTH_PROXY_MFA_ENCRYPTION_KEY=<openssl rand -hex 32>
AUTH_PROXY_GUEST_TOKEN_SECRET=<openssl rand -hex 32>
AUTH_PROXY_GUEST_TOKEN_API_KEY=<openssl rand -hex 32>
RUST_LOG=info
```

---

## CLIリファレンス

auth-proxy は以下のサブコマンドを持っています。

| コマンド | 説明 |
|---|---|
| `serve` | サーバー起動 |
| `init-admin` | 最初の管理者ユーザーを対話的に作成 |
| `hash` | パスワードの Argon2id ハッシュを生成 |
| `verify <username>` | ユーザーのパスワードを検証（デバッグ用） |
| `list` | 登録済みユーザーを一覧表示 |

### 静的ファイルモード（シングルバイナリ）の場合

バイナリを直接実行できます。

```bash
auth-proxy init-admin
auth-proxy list
auth-proxy verify alice
auth-proxy hash
```

### プロキシモード（Docker）の場合

コンテナ内のバイナリに対して `docker compose exec` または `docker compose run` 経由で実行します。**直接ターミナルから `auth-proxy` コマンドは実行できません。**

```bash
# サーバーが起動している状態で実行するコマンド（exec）
docker compose exec auth-proxy auth-proxy list
docker compose exec auth-proxy auth-proxy verify alice
docker compose exec auth-proxy auth-proxy hash

# サーバーを起動せずに一時コンテナで実行するコマンド（run）
# init-admin はサーバー起動前に実行するため run を使う
docker compose run --rm auth-proxy init-admin
```

`exec` と `run` の使い分けですが、`exec` は起動中のコンテナに入って実行します。`run` は新しい一時コンテナを起動して実行し、終了後に削除します（`--rm`）。`init-admin` のようにサーバーがまだ起動していない初回セットアップ時に使うのが `run` です。

---

## 上流サービスへのヘッダー伝達

**プロキシモードのみ適用されます。**静的ファイルモードではこの章は関係ありません。

認証済みリクエストを転送する際、auth-proxyは以下のヘッダーを付与して、上流サービスに渡します。

| ヘッダー | 内容 | 例 |
|---|---|---|
| `X-Auth-User` | ユーザー名 | `alice` |
| `X-Auth-User-Id` | ユーザーID（変更されない数値。OIDC の `sub` 相当） | `42` |
| `X-Auth-Role` | ロール | `admin` または `user` |
| `X-Auth-Issuer` | `AUTH_PROXY_ISSUER_NAME` の値 | `auth-proxy` |
| `X-Auth-Guest` | ゲストトークンアクセス時のみ `true`。通常セッションには付与しない | `true` |

ユーザー名は変更される可能性があるため、上流サービスが永続的にユーザーを識別する場合は `X-Auth-User-Id` を主キーとして扱ってください。

### 実装例

```python
# Python (Flask)
@app.route("/")
def index():
    user_id  = request.headers.get("X-Auth-User-Id")   # "42"
    username = request.headers.get("X-Auth-User")       # "alice"
    role     = request.headers.get("X-Auth-Role")       # "user" | "admin"
    # 認証処理は不要。ヘッダーを読むだけでよい
```

```go
// Go
func handler(w http.ResponseWriter, r *http.Request) {
    userID   := r.Header.Get("X-Auth-User-Id")   // "42"
    username := r.Header.Get("X-Auth-User")       // "alice"
    role     := r.Header.Get("X-Auth-Role")       // "user" | "admin"
}
```

---

## ゲストトークン機能

ログイン不要の限定公開アクセスを、認証の文脈で一元管理できる機能です。上流サービスはどのパスを共有するかを auth-proxy に伝えるだけでよく、トークン生成・検証・期限管理はすべて auth-proxy が行います。

### トークン発行

```bash
curl -X POST https://your-domain/api/guest-token \
  -H "Authorization: Bearer <AUTH_PROXY_GUEST_TOKEN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/shared/report",
    "expires_in": 86400,
    "max_uses": 10,
    "password": "secret123",
    "ui": {
      "title": "Q3レポート",
      "description": "招待メールに記載のパスワードを入力してください"
    }
  }'
```

| パラメータ | 必須 | 説明 |
|---|---|---|
| `path` | ✅ | アクセスを許可するパスプレフィックス（`/` で始まること） |
| `expires_in` | ✅ | 有効期間（秒） |
| `max_uses` | — | 最大アクセス回数。省略で無制限 |
| `password` | — | パスワード。省略するとURLのみでアクセス可能 |
| `ui.title` / `ui.description` | — | パスワード入力フォームに表示するテキスト |

### エンドユーザーのアクセス

```
https://your-domain/shared/report?guest_token=<token>
```

パスワードが設定されている場合はフォームが表示され、正しいパスワードを入力すると `guest_session_id` Cookie が発行されます。

---

## 運用

### ユーザー管理

ユーザー管理はブラウザの管理画面から行うのが基本です。CLIはデバッグや緊急時の補助手段として使います。

```bash
# ブラウザで管理画面を開く（両モード共通）
https://your-domain/admin/users
```

CLIでの確認（モードによって実行方法が異なります）:

```bash
# 静的ファイルモード（シングルバイナリ）
auth-proxy list
auth-proxy verify alice

# プロキシモード（Docker）
docker compose exec auth-proxy auth-proxy list
docker compose exec auth-proxy auth-proxy verify alice
```

### ログ確認

```bash
# 静的ファイルモード（systemd）
sudo journalctl -u auth-proxy -f
sudo journalctl -u auth-proxy -n 100

# プロキシモード（Docker）
docker compose logs -f auth-proxy
docker compose logs --tail=100 auth-proxy
```

---

## トラブルシューティング

### サーバーが起動しない

| エラー | 原因 | 対処 |
|---|---|---|
| `Neither AUTH_PROXY_SERVE_PATH nor AUTH_PROXY_UPSTREAM_APP_URL is set` | モード指定なし | いずれか一方または両方を `.env` に設定する |
| `Path does not exist: /path/to/...` | `AUTH_PROXY_SERVE_PATH` のディレクトリが存在しない | ディレクトリを作成するか、パスを修正する |
| `Address already in use` | ポートが使用中 | `AUTH_PROXY_LISTEN_ADDR` を変更するか競合プロセスを停止する |
| DBのパーミッションエラー | 書き込み権限なし | `/var/lib/auth-proxy` のオーナーをサービス実行ユーザーに変更する |

### ログインできない

まずログを確認してエラーメッセージを特定してみましょう。

```bash
# 静的ファイルモード
sudo journalctl -u auth-proxy -n 50

# プロキシモード（Docker）
docker compose logs --tail=50 auth-proxy
```

ユーザーの存在とパスワードを確認してみてください。

```bash
# 静的ファイルモード
auth-proxy list
auth-proxy verify alice

# プロキシモード（Docker）
docker compose exec auth-proxy auth-proxy list
docker compose exec auth-proxy auth-proxy verify alice
```

### 上流サービスに到達できない（プロキシモードのみ）

`AUTH_PROXY_UPSTREAM_APP_URL` のサービス名とポートが正しいか確認してみましょう。Dockerモードではホスト名にComposeのサービス名（例: `http://app:3000`）を使います。`localhost` や `127.0.0.1` はコンテナ内ではauth-proxy自身を指すため使用できません。

```bash
# auth-proxyコンテナから上流サービスに疎通できるか確認
docker compose exec auth-proxy wget -qO- http://app:3000 || echo "到達不可"

# 両サービスが同じネットワークに接続されているか確認
docker compose ps
docker network inspect <プロジェクト名>_internal
```

### コンテナが起動しない（プロキシモードのみ）

```bash
# 終了したコンテナのログも含めて確認
docker compose logs auth-proxy

# コンテナの状態を確認
docker compose ps -a
```

---

## プロジェクト構成

```
auth-proxy/
├── Cargo.toml
├── Cargo.lock
├── Dockerfile
├── docker-compose.example.yml
├── .env.auth-proxy.example
├── .dockerignore
├── migrations/                    # SQLite マイグレーションファイル
├── internal/                      # 仕様書（非公開）
└── src/
    ├── main.rs                    # エントリポイント・CLI ディスパッチ
    ├── config.rs                  # 環境変数読み込み・モード検証
    ├── users.rs                   # UserStore (Argon2id)
    ├── session.rs                 # SessionStore
    ├── mfa.rs                     # MfaStore (TOTP・バックアップコード・デバイス記憶)
    ├── state.rs                   # AppState（DB・HTTPクライアント）
    ├── router.rs                  # ルーティング定義
    ├── handlers/
    │   ├── login.rs               # GET/POST /login
    │   ├── logout.rs              # POST /logout
    │   ├── proxy.rs               # /* フォールバック（静的ファイル or 上流転送）
    │   ├── mfa.rs                 # MFA 検証フロー
    │   ├── settings/
    │   │   ├── mod.rs             # GET/POST /settings/mfa/*
    │   │   └── security.rs        # GET/POST /settings/security/*
    │   └── admin/
    │       ├── mod.rs
    │       ├── dashboard.rs       # GET /admin/
    │       └── users.rs           # GET/POST /admin/users/*
    ├── middleware/
    │   ├── auth.rs                # セッション検証・X-Auth-* 偽装防止
    │   └── admin.rs               # 管理者ロール確認
    └── cli/
        ├── hash.rs
        ├── verify.rs
        ├── list.rs
        └── init_admin.rs
```

---

## License

MIT
