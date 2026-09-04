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
- [ユーザー向けセキュリティ設定](#ユーザー向けセキュリティ設定)
- [APIトークン認証](#apiトークン認証)
- [上流サービスへのヘッダー伝達](#上流サービスへのヘッダー伝達)
- [ゲストトークン機能(計画中・未実装)](#ゲストトークン機能計画中未実装)
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
| Phase Docker | Dockerfile・Compose例・動作モード検証 | ✅ 実装済み |
| Phase Me | 安定した公開URL(`/me`)でのアカウント設定連携 | ✅ 実装済み |
| Phase API-1 | ブラウザ以外のクライアント向けBearer APIトークン認証(オプトイン) | ✅ 実装済み |
| Phase API-2 | 自分のAPIトークンを発行・失効するWeb UI(`/me/tokens`) | ✅ 実装済み |
| Phase API-3 | APIトークンのパススコープ制限(`path_prefix`) | ✅ 実装済み |
| Phase API-4 | CLIでのトークン管理・管理画面での全ユーザートークン可視化/失効 | ✅ 実装済み |
| Phase 4 | ゲストトークン機能（回数制限・パスワード付き共有リンク） | 🔜 予定 — **設計はあるが未実装**。詳細は後述 |
| Phase 3b | パスキー（WebAuthn） | 🔜 予定 |

---

## セキュリティ設計

### 静的ファイルモード

auth-proxyでHTTPリクエストを扱えます。`AUTH_PROXY_SERVE_PATH` 以下のファイルには承認されたユーザーのみ閲覧できるような制御をします。パストラバーサル（`../`等）は内部で防止しています。

### プロキシモード

プロキシモードではDockerを利用して、上流サービスと同じコンテナに入れ込みます。上流アプリは `ports:` を書かないことでホストや外部から直接アクセスできなくなります。認証されたユーザーのみauth-proxyを経由して上流サービスにアクセスできます。

上流サービスはauth-proxyより `X-Auth-*` ヘッダーを受け取り、ユーザー情報を判別できます。`X-Auth-*` ヘッダーはauth-proxy以外は書き込まないようにしているので、上流サービスはJWT署名検証などを実装する必要がなく、ビジネスロジックに集中できます。

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

### レート制限

auth-proxy自体はリクエストのレート制限を実装していません(理由は`docs/note/decisions/`の
ADR 0003を参照: APIトークンは256bitのランダム値なので、レート制限があってもなくても
総当たりは計算量的に不可能であり、汎用的なリクエスト量の制御は認証プロキシではなく
Traefikの責務と考えているため)。`/login`のパスワード総当たり対策や、一般的な悪用対策として
リクエスト量を制限したい場合は、Traefik側で設定してください。

```yaml
http:
  middlewares:
    auth-proxy-ratelimit:
      rateLimit:
        average: 100
        burst: 50
  routers:
    my-docs:
      rule: "Host(`docs.example.com`)"
      entryPoints:
        - websecure
      tls: {}
      middlewares:
        - auth-proxy-ratelimit
      service: auth-proxy-svc
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
    # ↓ いずれか一つを選択してコメントアウトを解除してください
    image: ghcr.io/DaisukeMatsuoh/auth-proxy:latest    # 【推奨】公開イメージを使う場合
    # build: .                                     # 【開発】ローカルでビルドする場合
    ports:
      # ホスト側のポート${AUTH_PROXY_HOST_PORT}と
      # コンテナ内のAuthProxyのListenポート${AUTH_PROXY_LISTEN_PORT}は
      # .envファイルで指定します。
      - "127.0.0.1:${AUTH_PROXY_HOST_PORT:-8080}:${AUTH_PROXY_LISTEN_PORT:-8080}"
    volumes:
      # ホスト側の ./data ディレクトリにマウントする。
      # コンテナを削除・再作成してもDBとデータは ./data に残る。
      - ./data:/var/lib/auth-proxy
    env_file:
      - .env.auth-proxy
    environment:
      # .envで設定するコンテナ内のAuthProxyのListenポートを
      # コンテナ内に環境変数として渡します
      AUTH_PROXY_LISTEN_PORT: ${AUTH_PROXY_LISTEN_PORT:-8080}
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
```

`AUTH_PROXY_UPSTREAM_APP_URL` はComposeのサービス名（上記のdocker-compose.ymlを利用している場合は `app`）を使って指定します。

```dotenv
# .env.auth-proxy
AUTH_PROXY_UPSTREAM_APP_URL=http://app:3000   # "app" はComposeのサービス名、3000はアプリのポート
```

アプリが別のポートでリッスンしている場合（例: 8000番）はそこを変更してください。サービス名はdocker-compose.ymlの `services:` の下のキー名に合わせること！

**ホスト側のポートについて**: docker-compose.yml の `ports:` 設定では `${AUTH_PROXY_HOST_PORT:-8080}` を使用しており、デフォルトは 8080 です。別のポートを使う場合はStep3の環境変数を設定してください。

---

### Step 3: 環境変数ファイルを作成する

```bash
cp .env.auth-proxy.example .env.auth-proxy
```

最低限以下を設定してください。どれもauth-proxyが参照します。

```dotenv
AUTH_PROXY_UPSTREAM_APP_URL=http://app:3000
AUTH_PROXY_DB_PATH=/var/lib/auth-proxy/auth-proxy.db  # docker-compose.ymlのマウント先に合わせること
AUTH_PROXY_LISTEN_ADDR=0.0.0.0   # コンテナ内のリッスンアドレス（固定値）
AUTH_PROXY_SESSION_TTL_HOURS=8
AUTH_PROXY_ISSUER_NAME=my-service
AUTH_PROXY_MFA_ENCRYPTION_KEY=xxx    # ← openssl rand -hex 32などで作成したランダムシードを記載
AUTH_PROXY_GUEST_TOKEN_SECRET=yyy    # 予約済み・未使用(計画中のゲストトークン機能用)
AUTH_PROXY_GUEST_TOKEN_API_KEY=zzz   # 予約済み・未使用(計画中のゲストトークン機能用)
```

**ポート設定について**:
- `AUTH_PROXY_LISTEN_ADDR=0.0.0.0` はコンテナ内部のリッスンアドレスで固定（変更不要）
- ホスト側のポートは docker-compose.yml の `${AUTH_PROXY_HOST_PORT:-8080}` で制御（環境変数で変更可）

**データの永続化について**:
- `./data:/var/lib/auth-proxy` のバインドマウントにより、DBファイルはホスト側の `./data/` ディレクトリに保存される
- `docker compose down` でコンテナを削除してもデータは `./data/` に残る（`AUTH_PROXY_DB_PATH` はこのマウント先に合わせて設定すること）
- `.env.auth-proxy` ファイルはホスト上に置くだけでよく、コンテナ再作成で消えることはない

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

auth-proxyのポート（`127.0.0.1:8080`）にTraefikまたはnginxから向けるように設定してください。8080は設定したポートに読み替えてください。以下は参考情報です:

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
| `AUTH_PROXY_LISTEN_ADDR` | — | `0.0.0.0` | Auth-proxyがリッスンするアドレス（コンテナ内部） |
| `AUTH_PROXY_LISTEN_PORT` | — | `8080` | Auth-proxyがリッスンするポート（コンテナ内部） |
| `AUTH_PROXY_HOST_PORT` | — | `8080` | docker-compose ホスト側がリッスンするポート(`.env` only, not `.env.auth-proxy`) |
| `AUTH_PROXY_SESSION_TTL_HOURS` | — | `8` | セッション有効期間（時間） |
| `AUTH_PROXY_ISSUER_NAME` | — | `auth-proxy` | `X-Auth-Issuer` ヘッダーの値 |
| `AUTH_PROXY_MFA_ENCRYPTION_KEY` | — | ※2 | TOTP シークレットの暗号化キー（hex 64文字） |
| `AUTH_PROXY_GUEST_TOKEN_SECRET` | — | ※2 | **予約済み・未使用** — パースはされるがどのコードからも参照されない。対応する機能([ゲストトークン機能](#ゲストトークン機能計画中未実装))自体が未実装 |
| `AUTH_PROXY_GUEST_TOKEN_API_KEY` | — | ※2 | **予約済み・未使用** — 上記と同様 |
| `AUTH_PROXY_API_TOKEN_ENABLED` | — | `false` | `Authorization: Bearer` によるAPIトークン認証を有効化(オプトイン)。[APIトークン認証](#apiトークン認証)を参照 |
| `AUTH_PROXY_API_TOKEN_DEFAULT_TTL_DAYS` | — | `0` | 新規発行するAPIトークンのデフォルト有効期限(日数)。`0`で無期限 |
| `RUST_LOG` | — | `info` | ログレベル（`trace` / `debug` / `info` / `warn` / `error`） |

※1 `AUTH_PROXY_SERVE_PATH` と `AUTH_PROXY_UPSTREAM_APP_URL` はいずれか一方または両方を設定してください。両方未設定の場合は起動エラーになります。

※2 デフォルト値はあるが本番環境では必ず `openssl rand -hex 32` で生成した値を設定してください。

**ポート設定について**:

| Scenario                       | Where to set      | Variables                | Value                                            |
| ------------------------------ | ----------------- | ------------------------ | ------------------------------------------------ |
| **Static File Mode** (systemd) | `.env.auth-proxy` | `AUTH_PROXY_LISTEN_ADDR` | `127.0.0.1` (address only)                       |
|                                |                   | `AUTH_PROXY_LISTEN_PORT` | `8080` (or desired port)                         |
| **Proxy Mode** (Docker)        | `.env`            | `AUTH_PROXY_HOST_PORT`   | `8080` (host-side port; where you connect from)  |
|                                |                   | `AUTH_PROXY_LISTEN_PORT` | `8080` (container-side port; must match)         |
|                                | `.env.auth-proxy` | `AUTH_PROXY_LISTEN_ADDR` | `0.0.0.0` (address only)                         |
|                                |                   | `AUTH_PROXY_LISTEN_PORT` | (not set; docker-compose.yml passes from `.env`) |

- **`AUTH_PROXY_LISTEN_ADDR`** (コンテナ内部):
  - シングルバイナリ（静的ファイルモード）: `.env` に `AUTH_PROXY_LISTEN_ADDR=127.0.0.1:8080` を明示
  - Docker モード: `0.0.0.0:8080` で固定（変更不要）
- **`AUTH_PROXY_HOST_PORT`** (ホスト側):
  - Docker Compose でのみ使用。環境変数で docker-compose.yml の `ports:` 設定を制御
  - 例: `AUTH_PROXY_HOST_PORT=9000 docker compose up` でホスト側のポートを 9000 に変更

**データ永続化について**:
- Docker モードでは `./data:/var/lib/auth-proxy` のバインドマウントを使用。DBファイルはホスト側 `./data/` に保存される
- `docker compose down` でコンテナを削除してもデータは残る（`-v` オプションをつけると削除されるので注意）
- `.env.auth-proxy` ファイルはホスト上に置くだけでよく、コンテナ再作成で消えることはない

### 設定例（静的ファイルモード）

```dotenv
AUTH_PROXY_SERVE_PATH=/var/www/html
AUTH_PROXY_DB_PATH=/var/lib/auth-proxy/auth-proxy.db
AUTH_PROXY_LISTEN_ADDR=127.0.0.1              # address part only
AUTH_PROXY_LISTEN_PORT=8080                   # port part
AUTH_PROXY_SESSION_TTL_HOURS=8
AUTH_PROXY_MFA_ENCRYPTION_KEY=<openssl rand -hex 32>
AUTH_PROXY_GUEST_TOKEN_SECRET=<openssl rand -hex 32>   # 予約済み・未使用
AUTH_PROXY_GUEST_TOKEN_API_KEY=<openssl rand -hex 32>  # 予約済み・未使用
RUST_LOG=info
```

### 設定例（プロキシモード / Docker）

**`.env`:**

```dotenv
AUTH_PROXY_HOST_PORT=8080          # host-side port (what Traefik/nginx connects to)
AUTH_PROXY_LISTEN_PORT=8080        # container-side port (must match docker-compose.yml)
```

**`.env.auth-proxy`:**

```dotenv
AUTH_PROXY_UPSTREAM_APP_URL=http://app:3000
AUTH_PROXY_DB_PATH=/var/lib/auth-proxy/auth-proxy.db  # must match the volume mount path in docker-compose.yml
AUTH_PROXY_LISTEN_ADDR=0.0.0.0                        # address part only
# AUTH_PROXY_LISTEN_PORT: do NOT set here; it comes from .env via docker-compose.yml
AUTH_PROXY_SESSION_TTL_HOURS=8
AUTH_PROXY_MFA_ENCRYPTION_KEY=<openssl rand -hex 32>
AUTH_PROXY_GUEST_TOKEN_SECRET=<openssl rand -hex 32>   # 予約済み・未使用
AUTH_PROXY_GUEST_TOKEN_API_KEY=<openssl rand -hex 32>  # 予約済み・未使用
RUST_LOG=info
```

## CLIリファレンス

auth-proxy は以下のサブコマンドを持っています。

| コマンド | 説明 |
|---|---|
| `serve` | サーバー起動 |
| `init-admin` | 最初の管理者ユーザーを対話的に作成 |
| `hash` | パスワードの Argon2id ハッシュを生成 |
| `verify <username>` | ユーザーのパスワードを検証（デバッグ用） |
| `list` | 登録済みユーザーを一覧表示 |
| `token list [--user <username>]` | APIトークンを一覧表示(全ユーザー、または指定ユーザーのみ) |
| `token revoke <id>` | 所有者に関わらずAPIトークンを失効 |
| `token create --user <username> --name <name> [--path-prefix </sync/>]` | APIトークンを発行し、平文トークンを1回だけ表示 |

### 静的ファイルモード（シングルバイナリ）の場合

バイナリを直接実行できます。

```bash
auth-proxy init-admin
auth-proxy list
auth-proxy verify alice
auth-proxy hash
auth-proxy token create --user alice --name "CIデプロイ用" --path-prefix /sync/
auth-proxy token list
auth-proxy token revoke 3
```

> **CI利用時の注意**: `token create` は平文トークンを標準出力に1回だけ表示します(二度と
> 取得できません)。CIパイプラインからこのコマンドを実行する場合、そのステップのログ出力を
> マスク/リダクトする設定にしてください。マスクしないと、CIシステムのログ保管先(CIのシークレット
> ストアより保護レベルが低いことが多い)にトークンが平文で残ってしまいます。

### プロキシモード（Docker）の場合

コンテナ内のバイナリに対して `docker compose exec` または `docker compose run` 経由で実行します。**直接ターミナルから `auth-proxy` コマンドは実行できません。**

```bash
# サーバーが起動している状態で実行するコマンド（exec）
docker compose exec auth-proxy auth-proxy list
docker compose exec auth-proxy auth-proxy verify alice
docker compose exec auth-proxy auth-proxy hash
docker compose exec auth-proxy auth-proxy token create --user alice --name "CIデプロイ用"

# サーバーを起動せずに一時コンテナで実行するコマンド（run）
# init-admin はサーバー起動前に実行するため run を使う
docker compose run --rm auth-proxy init-admin
```

`exec` と `run` の使い分けですが、`exec` は起動中のコンテナに入って実行します。`run` は新しい一時コンテナを起動して実行し、終了後に削除します（`--rm`）。`init-admin` のようにサーバーがまだ起動していない初回セットアップ時に使うのが `run` です。

---

## ユーザー向けセキュリティ設定

ログイン済みのすべてのユーザーが `/settings/security` から自分のアカウントのセキュリティ設定を管理できます。管理者の操作は不要です。

| 機能 | URL | 説明 |
|---|---|---|
| セキュリティ設定トップ | `/settings/security` | MFA状態・バックアップコード残数・デバイス記憶の一覧 |
| パスワード変更 | `/settings/security/password` | 現在のパスワードを確認した上で新しいパスワードに変更 |
| MFA有効化 | `/settings/security` → MFA設定ボタン | QRコードをスキャンしてTOTPを登録。完了時にバックアップコード8本を発行 |
| MFA無効化 | `/settings/security` → MFA無効化ボタン | 現在のパスワードを再確認して無効化。バックアップコード・デバイス記憶も同時に削除 |
| デバイス記憶の全削除 | `/settings/security` → デバイス削除ボタン | 「このデバイスを30日間記憶する」で保存したすべてのデバイストークンを削除 |
| APIトークン | `/me/tokens`（→ `/settings/security/tokens`） | ブラウザ以外のクライアント向けAPIトークンの発行・失効。詳細は[APIトークン認証](#apiトークン認証)を参照 |

### パスワード変更の流れ

```
/settings/security
    └── 「パスワードを変更する」リンク
            ↓
    /settings/security/password
        ・現在のパスワード
        ・新しいパスワード（8文字以上）
        ・新しいパスワード（確認）
            ↓ 送信
        検証成功 → パスワード更新 → /settings/security にリダイレクト
        検証失敗 → エラーメッセージ付きでフォームを再表示（500ms遅延）
```

### MFAの流れ

```
/settings/security
    └── 「二段階認証を有効にする」ボタン
            ↓
    QRコード表示（認証アプリでスキャン）
    または手動入力用シークレット（Base32）
            ↓ 確認コードを入力して送信
    バックアップコード8本を表示
    （この画面を離れると二度と表示されません）
            ↓
    MFA有効化完了 → 次回ログインからTOTPが要求される
```

---

## APIトークン認証

セッションCookieはブラウザには向いていますが、ネイティブアプリ・CLIツール・CIパイプラインは
Cookie jarや`SameSite=Strict`、認証失敗時の`302 → /login`リダイレクトをうまく扱えません。
APIトークンはこれを解決します。`Authorization: Bearer <token>`という長期有効なクレデンシャルで、
ルーティング・ヘッダーの観点ではセッションと同じように振る舞いますが、Cookieは一切発行せず、
認証失敗時は常にリダイレクトではなくJSONエラーを返します。

この機能は**デフォルト無効のオプトイン**です。有効化しても既存のセッションCookieの挙動は
一切変わりません。

```dotenv
# .env.auth-proxy
AUTH_PROXY_API_TOKEN_ENABLED=true
AUTH_PROXY_API_TOKEN_DEFAULT_TTL_DAYS=0   # 0 = デフォルトで無期限
```

### トークンの発行

機能を有効化すれば、以下の3つの同等な方法でユーザーのトークンを発行できます。

| 方法 | 手順 |
|---|---|
| Web UI(人間向け・推奨) | ログインして `/me/tokens`(→`/settings/security/tokens`にリダイレクト)へ。「新しいトークンを発行」をクリック |
| CLI(自動化・CI向け・推奨) | `auth-proxy token create --user <username> --name "<ラベル>" [--path-prefix </sync/>]` |
| JSON API(セッション認証必須) | `POST /api/tokens` に `{"name": "<ラベル>", "path_prefix": "/sync/"}` |

**平文トークンは発行時に1回だけ表示されます。** DBにはSHA-256ハッシュのみ保存されるため、
その後は二度と取得できません。紛失した場合は失効させて新しいトークンを発行してください。

```bash
curl -s -X POST https://your-domain/api/tokens \
  -H "Cookie: session_id=<あなたのセッションCookie>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice の MacBook"}'
# → {"id":1,"name":"Alice の MacBook","token":"apx_...","path_prefix":null}
```

### トークンの利用

```bash
curl -H "Authorization: Bearer apx_..." https://your-domain/sync/v1/logs
```

成功時はセッション認証済みのリクエストと全く同じように上流に転送され、
`X-Auth-Method: token` と `X-Auth-Token-Name: <ラベル>` が付与されます
（[上流サービスへのヘッダー伝達](#上流サービスへのヘッダー伝達)を参照）。失敗時は常に
`401`/`403` のJSONが返り、**`/login`へのリダイレクトにはなりません**（`Bearer`ヘッダーの存在が
「ブラウザ以外のクライアントである」ことを示すため）:

```json
{"error": "invalid_token", "error_description": "The access token is invalid or has been revoked"}
```

### パススコープ制限

トークンを特定のパスプレフィックに制限できます。漏洩したトークンが無関係なパス
（や管理画面）へアクセスするのを防げます。

```bash
auth-proxy token create --user alice --name "Sync service" --path-prefix /sync/
```

`/sync/`にスコープされたトークンは、`/sync/*` 以外へのリクエストで `403 insufficient_scope`
になります。`--path-prefix`を省略する(またはWeb UIで空欄にする)と、この機能導入前と同じ
全パスアクセス可能なトークンになります。

### トークンの失効

- **自分のトークン**: `/settings/security/tokens`、またはセッション認証下で
  `DELETE /api/tokens/{id}`(トークン自身では、自分自身を含めどのトークンも失効できません。
  常にセッション認証が必要です)。
- **任意ユーザーのトークン(管理者)**: `/admin/tokens`(管理ダッシュボードからリンク)、
  またはCLIの `auth-proxy token revoke <id>`。

### 設計上の注意点

- トークンは256bitのランダム値(`apx_<base64url>`)で、SHA-256でハッシュ化しています
  (Argon2idではありません — 低エントロピーのパスワードではなく高エントロピーな秘密情報に
  対する適切なトレードオフである理由は `docs/note/decisions/0001-api-token-bearer-auth.md`
  を参照)。
- auth-proxy自体にはAPIリクエストのレート制限機能はありません。256bitトークンの総当たりは
  レート制限の有無に関わらず計算量的に不可能なため、実装しても実際の脅威には対応できないと
  判断しています。汎用的なリクエスト量の制御(`/login`保護等)をしたい場合はTraefik側で
  設定してください([レート制限](#レート制限)、`docs/note/decisions/0003-cli-and-admin-token-visibility-rate-limit-to-traefik.md`を参照)。
- 各フェーズの設計判断は `docs/note/decisions/`(ADR 0001〜0003)と
  `docs/note/api-token-auth-runbook.md` に記録されています。ペアリングコード方式や
  アプリ内蔵のレート制限など、**意図的に実装しなかった**機能とその理由も含まれています。

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
| `X-Auth-Method` | 認証方式 | `session` または `token` |
| `X-Auth-Token-Name` | APIトークンの識別名(トークン認証時のみ) | `Alice の MacBook` |
| `X-Auth-Guest` | **未実装** — 計画中のゲストトークン機能用に予約(後述)。現状は一切送信されない | — |

ユーザー名は変更される可能性があるため、上流サービスが永続的にユーザーを識別する場合は `X-Auth-User-Id` を主キーとして扱ってください。セッション由来のトラフィックとトークン由来のトラフィックを区別したい場合(例: `/sync/*` はトークン認証のみ許可し、Web画面はセッション認証を要求する等)は `X-Auth-Method` を使ってください。詳細は[APIトークン認証](#apiトークン認証)を参照してください。

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

## ゲストトークン機能(計画中・未実装)

> ⚠️ **この機能はまだコードベースに存在しません。** `/api/guest-token` エンドポイントも
> `guest_session_id` Cookieも `X-Auth-Guest` ヘッダーも実装されておらず、以下のリクエストを
> 送っても `404` が返るだけです。このセクションは*将来のフェーズの設計意図*を記録するために
> 残してあります。誰かが本セクションを読まずに「なんとなく近い」実装を作ってしまうことを
> 防ぐ目的もあります。共有リンクのようなユースケースで今すぐ評価したい場合、この機能は
> まだ使えません。

想定している設計: ゲストトークンは、特定のパスへの限定的な未認証アクセスを、auth-proxy内で
一元管理できるようにするものです。上流サービスはどのパスを共有するかをauth-proxyに伝えるだけで
よく、トークン生成・検証・期限管理はすべてauth-proxyが行う想定でした。以下は
(実在しない、未実装の)想定していたAPIの形のスケッチです。

```bash
# 実在しないエンドポイントです — あくまでイメージ
curl -X POST https://your-domain/api/guest-token \
  -H "Authorization: Bearer <AUTH_PROXY_GUEST_TOKEN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/shared/report",
    "expires_in": 86400,
    "max_uses": 10,
    "password": "secret123"
  }'
```

`AUTH_PROXY_GUEST_TOKEN_SECRET` と `AUTH_PROXY_GUEST_TOKEN_API_KEY` は、パースはされるものの
どこからも参照されない設定項目として存在しています。実際に実装される日のためのプレースホルダーです。

---

## 運用

### ユーザー管理

ユーザー管理はブラウザの管理画面から行うのが基本です。CLIはデバッグや緊急時の補助手段として使います。

```bash
# ブラウザで管理画面を開く（両モード共通）
https://your-domain/admin/users
https://your-domain/admin/tokens   # 全ユーザーのAPIトークン。退職者対応時などに失効させる
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
| DBのパーミッションエラー | 書き込み権限なし | `./data` ディレクトリのオーナーをDockerが書き込める状態にする |
| `docker compose down -v` 後にデータが消えた | `-v` オプションはボリュームも削除する | バインドマウント（`./data`）を使っている場合は `-v` を付けても `./data` 自体は消えないが、念のため `down` のみ使用することを推奨 |

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
├── migrations/                    # SQLite マイグレーションファイル(追記のみ。既存ファイルは変更しない)
├── docs/note/                     # 設計判断の記録(ADR)と実装runbook
├── internal/                      # 仕様書（非公開）
└── src/
    ├── main.rs                    # エントリポイント・CLI ディスパッチ
    ├── config.rs                  # 環境変数読み込み・モード検証
    ├── state.rs                   # AppState（Arc化された各ストア・DBプール・HTTPクライアント。マイグレーション実行もここ）
    ├── router.rs                  # ルーティング定義
    ├── users.rs                   # APP_USERS/AUTH_PROXY_USERS のシード形式パーサーのみ。実運用のストアではない
    ├── users_db.rs                # UserStoreDb — 実際に使われるSQLiteベースのユーザーストア(Argon2id)
    ├── session.rs                 # インメモリ版SessionStore — デッドコード(自身の単体テストのためだけに残存)
    ├── sessions_db.rs             # SessionStoreDb — 実際に使われるSQLiteベースのセッションストア
    ├── api_tokens_db.rs           # ApiTokenStoreDb — Bearer APIトークンの発行・検証・失効(SHA-256ハッシュ)
    ├── mfa.rs                     # MfaStore (TOTP・バックアップコード・デバイス記憶)
    ├── handlers/
    │   ├── login.rs               # GET/POST /login
    │   ├── logout.rs              # POST /logout
    │   ├── proxy.rs               # /* フォールバック（静的ファイル or 上流転送）
    │   ├── static_files.rs        # 静的ファイル配信（AUTH_PROXY_SERVE_PATHモード）
    │   ├── mfa.rs                 # MFA 検証フロー
    │   ├── me.rs                  # GET /me, /me/password, /me/mfa, /me/devices, /me/tokens（安定リダイレクトURL）
    │   ├── api_tokens.rs          # GET/POST /api/tokens, DELETE /api/tokens/{id}（セッション認証のみ）
    │   ├── settings/
    │   │   ├── mod.rs             # GET/POST /settings/mfa/*
    │   │   ├── security.rs        # GET/POST /settings/security/*
    │   │   └── tokens.rs          # GET/POST /settings/security/tokens（自分のAPIトークン）
    │   └── admin/
    │       ├── mod.rs
    │       ├── dashboard.rs       # GET /admin/
    │       ├── users.rs           # GET/POST /admin/users/*
    │       └── tokens.rs          # GET /admin/tokens, POST /admin/tokens/{id}/revoke（全ユーザーのトークン）
    ├── middleware/
    │   ├── auth.rs                # Bearer/セッション認証解決・X-Auth-* 偽装防止・パススコープ検証
    │   └── admin.rs                # AuthUserの定義。admin_middleware関数は存在するが未配線（デッドコード）
    └── cli/
        ├── hash.rs
        ├── verify.rs
        ├── list.rs
        ├── init_admin.rs
        └── token.rs               # `auth-proxy token list/revoke/create`
```

---

## License

MIT
