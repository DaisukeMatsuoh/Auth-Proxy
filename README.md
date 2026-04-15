# auth-proxy

静的HTMLファイルをセッション認証付きで配信する、Rust (Axum) 製の軽量プロキシサーバーです。
既存の EC2 + Traefik 構成の背後に配置し、認証済みユーザーにのみコンテンツを限定公開します。

## 目次

- [概要とアーキテクチャ](#概要とアーキテクチャ)
- [セキュリティ設計](#セキュリティ設計)
- [必要環境](#必要環境)
- [ビルド](#ビルド)
- [初回セットアップ](#初回セットアップ)
- [環境変数リファレンス](#環境変数リファレンス)
- [CLIコマンドリファレンス](#cliコマンドリファレンス)
- [ユーザー管理](#ユーザー管理)
- [HTMLファイルの配置ルール](#htmlファイルの配置ルール)
- [Traefik連携設定](#traefik連携設定)
- [運用手順](#運用手順)
- [トラブルシューティング](#トラブルシューティング)
- [プロジェクト構成](#プロジェクト構成)

---

## 概要とアーキテクチャ

```
[ブラウザ]
    │ HTTPS
    ▼
[Traefik]  ← TLS終端・リバースプロキシ
    │ HTTP (ローカル)
    ▼
[auth-proxy (本サーバー)]
    ├── GET/POST /login   → フォーム認証 (Argon2id)
    ├── GET      /logout  → セッション削除
    └── GET      /*       → セッション検証 → APP_SERVE_PATH からHTML配信
                              未認証の場合は /login にリダイレクト
```

**設計上の主要な決定事項:**

| 項目 | 採用技術・方針 | 理由 |
|---|---|---|
| 認証方式 | フォームログイン + HttpOnly Cookie | ブラウザアクセス前提。localStorage不要でXSSリスクを排除 |
| セッション管理 | オンメモリ `HashMap` | 数十人規模。Redisなど外部依存なし。再起動でクリアされることを許容 |
| ユーザーストア | 環境変数 | DB不要な規模感。型安全な読み取りでインジェクションリスクなし |
| パスワードハッシュ | Argon2id | OWASPが推奨するメモリハード設計。平文は一切保存しない |
| ファイル配信 | `tower-http` ServeDir | ディレクトリトラバーサルを自動防止。他部署が独立してHTML管理可能 |
| TLS | Traefikに委譲 | 既存インフラを変更しない |

---

## セキュリティ設計

本サーバーは以下の脅威に対して多層防御を実装しています。

### Cookie属性

発行するセッションCookieには以下の属性をすべて付与します。いずれか一つでも欠けると脆弱性になるため、実装変更時は注意してください。

```
Set-Cookie: session_id=<token>; HttpOnly; Secure; SameSite=Strict; Max-Age=<TTL秒>
```

| 属性 | 目的 |
|---|---|
| `HttpOnly` | JavaScriptからのCookieアクセスを遮断 → XSS経由のセッション窃取防止 |
| `Secure` | HTTPS経由でのみ送信 → 平文通信での漏洩防止 |
| `SameSite=Strict` | クロスサイトリクエストでCookieを送信しない → CSRF防止 |
| `Max-Age` | デフォルト8時間 (28800秒)。`APP_SESSION_TTL_HOURS` で変更可能 |

### パスワード保護

- パスワードは **Argon2id** でハッシュ化して環境変数に保存。**平文は一切保存・ログ出力しない**
- ログイン失敗時は意図的に500ms遅延させ、ブルートフォース攻撃を抑止
- 存在しないユーザー名でもダミーのArgon2検証を実行し、応答時間によるユーザー名列挙を防止
- ログイン失敗時のエラーメッセージは「ユーザー名またはパスワードが違います」とし、どちらが間違っているかを開示しない

### セッションID

`rand::rngs::OsRng`（暗号論的乱数生成器）で生成した128bit (16バイト) をhex文字列化した32文字。`thread_rng` は使用しない。

### ディレクトリトラバーサル防止

ファイル配信は `tower-http` の `ServeDir` を使用し、`../` などによるパス操作を自動的にブロックします。直接ファイルパスを組み立てる処理は実装していません。

---

## 必要環境

- Rust 1.75 以上 (`cargo` 付属)
- Linux (Ubuntu 22.04 LTS 以降推奨)
- Traefik が同一ホストまたはリバースプロキシとして動作していること
- systemd (サービス管理用)

---

## ビルド

```bash
# EC2 (Linux) 上でビルドする場合
cargo build --release
# → target/release/auth-proxy が生成される

# ローカルMac → Linux向けクロスコンパイル
cargo install cross
cross build --release --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/auth-proxy が生成される
```

---

## 初回セットアップ

```bash
# 1. バイナリを配置
sudo cp target/release/auth-proxy /usr/local/bin/

# 2. 設定ディレクトリと .env ファイルを作成
sudo mkdir -p /etc/auth-proxy
sudo cp .env.example /etc/auth-proxy/.env
sudo chown root:root /etc/auth-proxy/.env
sudo chmod 600 /etc/auth-proxy/.env   # root以外から読めないように必ず設定すること

# 3. セッションシークレットを生成して .env に記入
openssl rand -hex 64
# → 出力をコピーして APP_SESSION_SECRET に設定

# 4. 最初のユーザーを追加 (次の「ユーザー管理」セクション参照)
auth-proxy hash

# 5. systemdサービスを登録・起動
sudo cp systemd/auth-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable auth-proxy
sudo systemctl start auth-proxy

# 6. 起動確認
sudo systemctl status auth-proxy
```

---

## 環境変数リファレンス

`/etc/auth-proxy/.env` に以下を記述します。`.env.example` をテンプレートとして使用してください。

| 変数名 | 必須 | デフォルト | 説明 |
|---|---|---|---|
| `APP_USERS` | ✅ | — | `username:argon2hash` をカンマ区切りで列挙。詳細は下記参照 |
| `APP_SESSION_SECRET` | ✅ | — | セッション署名用シークレット。64バイト以上のランダム文字列 |
| `APP_SERVE_PATH` | ✅ | — | 配信するHTMLが置かれたディレクトリの絶対パス |
| `APP_LISTEN_ADDR` | — | `127.0.0.1:8080` | サーバーがListenするアドレスとポート |
| `APP_SESSION_TTL_HOURS` | — | `8` | セッション有効期限（時間単位） |
| `RUST_LOG` | — | `info` | ログレベル (`trace` / `debug` / `info` / `warn` / `error`) |

### .env ファイルの記述例

```dotenv
# シングルクォートで囲むこと。$記号がシェルに展開されるのを防ぐために必須。
APP_USERS='alice:$argon2id$v=19$m=19456,t=2,p=1$SALT1$HASH1,bob:$argon2id$v=19$m=19456,t=2,p=1$SALT2$HASH2'

APP_SESSION_SECRET=ここにopenssl rand -hex 64の出力を貼り付ける

APP_SERVE_PATH=/var/www/html

APP_LISTEN_ADDR=127.0.0.1:8080

APP_SESSION_TTL_HOURS=8

RUST_LOG=info
```

> **⚠️ 重要: `APP_USERS` のシングルクォート**
>
> Argon2のPHC文字列は `$argon2id$v=19$...` のように `$` 記号を含みます。`.env` ファイルに記述する際、`$` がシェル変数として展開されるのを防ぐため、**必ずシングルクォートで値全体を囲んでください**。ダブルクォートでは `$` が展開されてハッシュが破損します。

---

## CLIコマンドリファレンス

```
auth-proxy serve           サーバーを起動する（引数なし時のデフォルト動作）
auth-proxy hash            パスワードのArgon2idハッシュを対話的に生成する
auth-proxy verify <user>   指定ユーザーのパスワードを対話的に検証する（デバッグ用）
auth-proxy list            APP_USERSに登録されているユーザー名一覧を表示する
```

---

## ユーザー管理

### ユーザーの追加

```bash
# 1. ハッシュを生成（パスワードはプロンプトで入力。画面には表示されない）
auth-proxy hash
# 出力例:
# $argon2id$v=19$m=19456,t=2,p=1$xxxx$yyyy

# 2. .env を編集して APP_USERS に追記
#    alice と bob が既存の場合に carol を追加する例:
sudo vim /etc/auth-proxy/.env
# APP_USERS='alice:$argon2id$...,bob:$argon2id$...,carol:$argon2id$v=19$m=19456,t=2,p=1$xxxx$yyyy'

# 3. サービスを再起動（既存セッションはすべてクリアされる点に注意）
sudo systemctl restart auth-proxy

# 4. 登録を確認
auth-proxy list
```

### ユーザーの削除

```bash
# 1. .env から該当ユーザーのエントリを削除
sudo vim /etc/auth-proxy/.env

# 2. 再起動（削除したユーザーのセッションも含め、全セッションがクリアされる）
sudo systemctl restart auth-proxy
```

> **注:** セッションはオンメモリで管理しているため、サービス再起動により**すべてのユーザーがログアウト**されます。ユーザー追加・削除は業務時間外や利用者の少ない時間帯に実施することを推奨します。

### パスワードの変更

1. `auth-proxy hash` で新しいハッシュを生成
2. `.env` の `APP_USERS` で該当ユーザーのハッシュ部分を置き換え
3. `sudo systemctl restart auth-proxy`

---

## HTMLファイルの配置ルール

`APP_SERVE_PATH` で指定したディレクトリ配下のファイルがそのままURLパスにマッピングされます。

### ディレクトリ構造とURLの対応例

`APP_SERVE_PATH=/var/www/html` の場合:

```
/var/www/html/
├── index.html          → https://example.com/
├── tool-a/
│   └── index.html      → https://example.com/tool-a/
└── tool-b/
    ├── index.html      → https://example.com/tool-b/
    └── assets/
        └── style.css   → https://example.com/tool-b/assets/style.css
```

### HTMLファイルを置く際の注意事項

**ファイルパーミッション**

`auth-proxy` プロセスの実行ユーザー（デフォルト: `www-data`）がファイルを読み取れるように設定してください。

```bash
# HTMLディレクトリをwww-dataが読めるように設定
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html
```

**ファイル名の制限**

- ファイル名に `..` を含むパスは `tower-http` が自動的にブロックします
- ファイル名にURLエンコードが必要な文字（スペース、日本語など）を使用しないことを推奨します
- シンボリックリンクは `APP_SERVE_PATH` の外部を指さないようにしてください（意図しないファイルが公開されるリスクがあります）

**外部リソースの参照**

HTMLファイルがCDNや外部APIを参照している場合、エンドユーザーのブラウザから直接アクセスが発生します。本サーバーはファイル配信のみを制御しており、HTMLが読み込む外部リソースへのアクセスは制御しません。機密性の高い情報を含むページでは外部リソースの参照を最小限にしてください。

**動的コンテンツは非対応**

本サーバーは**静的ファイルの配信のみ**に対応しています。PHP、CGI、サーバーサイドJavaScriptなどの動的処理は実行されません。JavaScriptを含む静的HTMLは問題なく配信されます。

**ホットリロード**

`APP_SERVE_PATH` 配下のファイルはサービス再起動なしに随時更新・追加・削除できます。変更はブラウザの次回リクエスト時に即時反映されます。

---

## Traefik連携設定

Traefikのdynamic configに以下を追加してください。

```yaml
# /etc/traefik/dynamic/auth-proxy.yml
http:
  routers:
    auth-proxy:
      rule: "Host(`tool.internal.example.com`)"
      entryPoints:
        - websecure
      tls: {}
      service: auth-proxy

  services:
    auth-proxy:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8080"
```

> **注:** `APP_LISTEN_ADDR` と Traefik の `url` のポートが一致していることを確認してください。CookieのSecure属性はHTTPS通信を前提としているため、**TraefikでTLSを有効にしていない環境ではCookieが送信されません**。

---

## 運用手順

### 初回セットアップチェックリスト

- [ ] `APP_SESSION_SECRET` に十分なランダム性のある文字列を設定した (`openssl rand -hex 64`)
- [ ] `.env` ファイルのパーミッションが `600` であることを確認した
- [ ] `APP_SERVE_PATH` が正しいHTMLディレクトリを指していることを確認した
- [ ] TraefikのHTTPS設定が有効であることを確認した
- [ ] `auth-proxy list` でユーザーが正しく登録されていることを確認した

### 日常的なユーザー管理コマンド

```bash
# ユーザー一覧確認
auth-proxy list

# 特定ユーザーのパスワード検証テスト
auth-proxy verify alice
```

### ログ確認

```bash
# リアルタイムでログを追う
sudo journalctl -u auth-proxy -f

# 直近100行を確認
sudo journalctl -u auth-proxy -n 100

# エラーのみ抽出
sudo journalctl -u auth-proxy -p err
```

### サービス操作

```bash
# 状態確認
sudo systemctl status auth-proxy

# 再起動（全セッションクリア）
sudo systemctl restart auth-proxy

# 停止 / 起動
sudo systemctl stop auth-proxy
sudo systemctl start auth-proxy
```

---

## トラブルシューティング

### サービスが起動しない

```bash
sudo journalctl -u auth-proxy -n 50
```

よくある原因と対処:

| エラー内容 | 原因 | 対処 |
|---|---|---|
| `APP_SESSION_SECRET is not set` | 環境変数が未設定 | `.env` を確認し必須項目を設定 |
| `APP_SERVE_PATH does not exist` | パスが存在しない | ディレクトリを作成するか正しいパスを設定 |
| `Address already in use` | ポートが使用中 | `APP_LISTEN_ADDR` を変更するか競合プロセスを停止 |
| `Permission denied` on serve path | ファイル読み取り権限なし | `www-data` がHTMLディレクトリを読めるようにchownする |

### ログインできない

```bash
# パスワードが正しいかを確認
auth-proxy verify <username>

# APP_USERS にユーザーが登録されているか確認
auth-proxy list
```

`.env` の `APP_USERS` を編集した場合は必ず `sudo systemctl restart auth-proxy` を実行してください。環境変数は起動時にのみ読み込まれます。

### ファイルが404になる

- `APP_SERVE_PATH` の設定値を確認する
- ファイルが `www-data` から読み取れるか権限を確認する (`ls -la /var/www/html/`)
- URLパスとファイルシステムのパスが一致しているか確認する

### セッションがすぐ切れる

`APP_SESSION_TTL_HOURS` の値を確認し、必要に応じて延長してください。デフォルトは8時間です。

---

## プロジェクト構成

```
auth-proxy/
├── Cargo.toml
├── Cargo.lock
├── .env.example               # 環境変数のサンプル（値はプレースホルダー）
├── .gitignore                 # .env は必ずgitignoreに含めること
├── README.md
├── systemd/
│   └── auth-proxy.service     # systemdユニットファイル
└── src/
    ├── main.rs                # エントリーポイント・CLIディスパッチ
    ├── config.rs              # 環境変数読み込みと検証
    ├── users.rs               # ユーザーストア（Argon2id検証）
    ├── session.rs             # セッションストア（HashMap + TTL管理）
    ├── handlers/
    │   ├── login.rs           # GET/POST /login
    │   ├── logout.rs          # GET /logout
    │   └── static_files.rs    # GET /* （ファイル配信）
    ├── middleware/
    │   └── auth.rs            # セッションCookie検証ミドルウェア
    └── cli/
        ├── hash.rs            # hash サブコマンド
        ├── verify.rs          # verify サブコマンド
        └── list.rs            # list サブコマンド
```

---

## ライセンス

このプロジェクトは社内利用を目的としています。
