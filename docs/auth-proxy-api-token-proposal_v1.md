# auth-proxy 機能追加提案 — API トークン認証（Phase API）

**提案元**: timetrack プロジェクト
**日付**: 2026/08/31
**対象**: auth-proxy 実装仕様書 v10 への追記提案
**ステータス**: 提案（未承認）

---

## 1. 背景と課題

### 1.1 現状

auth-proxy は現在、以下の2つの認証経路を持つ。

| 経路 | 認証方式 | 想定クライアント |
|---|---|---|
| 通常認証 | セッション Cookie（`HttpOnly; Secure; SameSite=Strict`） | ブラウザ |
| ゲストトークン | URL 埋め込みトークン + ゲストセッション Cookie | ブラウザ（共有リンク経由） |

いずれも **Cookie を前提としており、ブラウザ以外のクライアントを想定していない**。

### 1.2 発生している課題

timetrack（活動ログシステム）が、オフライン記録を可能にするため
**Mac / Windows のネイティブ常駐アプリ** を持つ構成に変更された。

このアプリはネットワーク接続時にサーバーへ活動ログを同期するが、
現状の auth-proxy ではこの同期リクエストを認証できない。

具体的な障害は以下の通り。

1. **Cookie ベースの認証はネイティブアプリで扱いにくい**
   Cookie jar の実装、`SameSite=Strict` の解釈、リダイレクト追従など、
   ブラウザが暗黙に処理している挙動をアプリ側で再実装する必要がある

2. **セッション TTL（デフォルト8時間）が短すぎる**
   常駐アプリが毎日パスワード再入力を求めるのは体験として成立しない

3. **認証失敗時の挙動がブラウザ向け**
   未認証時に `302 → /login` が返るため、API クライアントは
   ログイン HTML を受け取ってしまい、エラーハンドリングができない

### 1.3 回避策を検討したが不採用とした案

| 案 | 内容 | 不採用の理由 |
|---|---|---|
| ゲストトークンの流用 | Phase 4 のゲストトークンを長期トークンとして使う | 本来「共有リンク用」であり、ユーザーID が紐づかない（`X-Auth-User-Id` が付与されない）ため、誰のログか判別できない |
| auth-proxy をバイパス | `/sync/*` のみ Traefik で上流に直接ルーティング | 上流サービスがホストにポートを公開する必要が生じ、**auth-proxy の中核的な設計思想（ネットワーク隔離による偽装防止）が崩れる**。上流側が独自にトークン検証を実装する責任も発生し、「上流サービスの認証負担ゼロ」という思想にも反する |

**上記の検討結果、auth-proxy 自体に API トークン認証を実装することが、
設計思想を維持したまま課題を解決する唯一の方法であると判断した。**

---

## 2. 提案の要旨

auth-proxy に **`Authorization: Bearer <token>` によるAPI トークン認証** を追加する。

これにより、

- 上流サービスは引き続き `ports:` を公開せず、`internal: true` ネットワークに閉じたままでよい
- 上流サービスは引き続き `X-Auth-*` ヘッダーを読むだけでよく、認証実装を持たない
- ブラウザ以外のクライアント（デスクトップアプリ・CLI・CI 等）が auth-proxy 配下のサービスを利用できる

という状態を実現する。

**auth-proxy の設計思想「上流サービスの認証負担ゼロ」を、
ブラウザ以外のクライアントにも拡張する提案である。**

---

## 3. 認証フロー全体像

```mermaid
sequenceDiagram
    participant B as ブラウザ
    participant AP as auth-proxy
    participant D as デスクトップアプリ
    participant U as 上流サービス

    Note over B,AP: ① トークン発行（ブラウザ・セッション認証下）
    B->>AP: POST /api/tokens {name:"Alice の MacBook"}
    AP-->>B: {token:"apx_xxx...", id:12}<br/>※ 平文はこの1回のみ返す

    Note over B,D: ② ユーザーがトークンをアプリに設定
    B-->>D: コピー&ペースト（または後述のペアリングコード）

    Note over D,U: ③ 以降の API アクセス
    D->>AP: POST /sync/v1/logs<br/>Authorization: Bearer apx_xxx...
    AP->>AP: トークン検証（SHA-256 ハッシュ照合）
    AP->>AP: クライアント由来の X-Auth-* を除去
    AP->>U: X-Auth-User: alice<br/>X-Auth-User-Id: 42<br/>X-Auth-Role: user<br/>X-Auth-Method: token
    U-->>AP: 200 OK
    AP-->>D: 200 OK
```

---

## 4. 要求機能一覧

優先度は timetrack 側の実装ブロッカーになるかどうかで判定している。

| # | 機能 | 優先度 | 概要 |
|---|---|---|---|
| R1 | Bearer トークン認証ミドルウェア | **必須** | `Authorization: Bearer` を検証し、成功時に `X-Auth-*` を付与して上流転送 |
| R2 | `api_tokens` テーブル | **必須** | トークンのハッシュ・所有者・失効状態を管理 |
| R3 | API クライアント向けエラー応答 | **必須** | 認証失敗時に `302` ではなく `401` + JSON を返す |
| R4 | トークン発行・失効の Web UI | **必須** | ユーザーが自分でトークンを発行・一覧・失効できる |
| R5 | `X-Auth-Method` ヘッダー | **必須** | 上流が「セッション認証」と「トークン認証」を区別できるようにする |
| R6 | ペアリングコード方式 | 推奨 | トークン文字列のコピペを避け、短いコードで端末を登録する |
| R7 | トークンのパススコープ制限 | 推奨 | トークンごとにアクセス可能なパス prefix を制限する |
| R8 | レート制限 | 推奨 | トークン単位でのリクエスト頻度制限 |
| R9 | CLI サブコマンド | 任意 | `auth-proxy token list` 等での運用操作 |
| R10 | 管理画面でのトークン可視化 | 任意 | 管理者が全ユーザーのトークン発行状況を確認・失効できる |

---

## 5. 詳細仕様（提案）

### R1. Bearer トークン認証ミドルウェア

#### 判定順序

既存の `auth_middleware` の**先頭**にトークン判定を挿入する。

```
リクエスト受信
  ↓
① Authorization ヘッダーに "Bearer " がある？
  ├─ Yes → トークン検証
  │         ├─ 成功 → AuthContext::Authenticated(user) として続行
  │         └─ 失敗 → 401 JSON を返す（/login へリダイレクトしない）
  └─ No  → ② 既存のセッション Cookie 判定へ
            ├─ 成功 → 従来通り
            └─ 失敗 → 302 /login（従来通り）
```

**重要**: `Authorization: Bearer` が存在する時点で「API クライアントである」と判定し、
失敗時にリダイレクトを返さないこと。これがないとアプリ側でエラー処理ができない。

#### トークン形式

```
apx_<base64url(32バイトのランダム値)>

例: apx_kJ8xQ2mN7pR4tY6wZ1aB3cD5eF9gH0iL2nO4qS6uV8x
```

- プレフィックス `apx_` を付ける理由: 誤ってソースコードにコミットされた際に
  GitHub の Secret Scanning 等で検出しやすくするため（GitHub / Stripe 等の慣行に倣う）
- 乱数は既存のセッションID生成と同様に **`rand::rngs::OsRng` を使用**すること
  （`thread_rng` は使用禁止という既存方針を踏襲）

#### ハッシュ方式の指定と根拠

**保存は SHA-256 のハッシュとし、Argon2id は使用しないことを提案する。**

これは既存のパスワード保存方針（Argon2id）とは意図的に異なる。理由は以下の通り。

| | パスワード | API トークン |
|---|---|---|
| エントロピー | 低い（人間が作る） | **高い（256bit の乱数）** |
| 総当たり攻撃の現実性 | あり | **計算量的に不可能** |
| 検証頻度 | ログイン時のみ（低頻度） | **全リクエスト（高頻度）** |
| 適切なハッシュ | Argon2id（意図的に低速） | **SHA-256（高速）** |

Argon2id は「低エントロピーの秘密を総当たりから守るために意図的に遅くする」アルゴリズムである。
256bit の乱数トークンに適用すると、**得られる安全性の向上はゼロに近い一方、
全リクエストに数十〜数百ミリ秒の遅延が乗る**。

auth-proxy の設計思想である「ノンブロッキング」「非力なハードウェアでも動作」に照らして、
API トークンには SHA-256 を用いるべきである。

> なお、SHA-256 ハッシュでの保存により、DB が漏洩しても平文トークンは復元できない
> という保護は維持される。

#### 検証処理

```
1. Authorization ヘッダーから "Bearer " 以降を取り出す
2. SHA-256 でハッシュ化する
3. api_tokens テーブルを token_hash で検索（インデックス使用）
4. 以下をすべて確認する
   - レコードが存在する
   - revoked_at が NULL
   - expires_at が NULL または未来
   - 紐づく users.id が存在し、有効である
5. last_used_at を更新する（後述の注意点を参照）
6. AuthContext を構築して次の処理へ渡す
```

**`last_used_at` の更新に関する注意**: 毎リクエストで UPDATE を発行すると
SQLite の書き込みロックが頻発し、「ノンブロッキング」の設計思想に反する。
以下のいずれかの緩和策を推奨する。

- 前回更新から一定時間（例: 5分）経過している場合のみ更新する
- 更新をメモリ上にバッファし、定期的にまとめて書き込む

### R2. `api_tokens` テーブル

```sql
CREATE TABLE api_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    token_hash    TEXT    NOT NULL UNIQUE,  -- SHA-256 hex（平文は保存しない）
    name          TEXT    NOT NULL,          -- "Alice の MacBook" 等の識別名
    path_prefix   TEXT,                      -- R7。NULL の場合は全パス許可
    expires_at    TEXT,                      -- NULL の場合は無期限
    last_used_at  TEXT,
    revoked_at    TEXT,                      -- 失効時に設定。NULL なら有効
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_api_tokens_token_hash ON api_tokens(token_hash);
CREATE INDEX idx_api_tokens_user_id    ON api_tokens(user_id);
```

`ON DELETE CASCADE` により、ユーザー削除時にトークンも自動的に削除される。

### R3. API クライアント向けエラー応答

`Authorization: Bearer` を伴うリクエストの認証失敗時は、以下を返す。

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
WWW-Authenticate: Bearer

{
  "error": "invalid_token",
  "error_description": "The access token is invalid or has been revoked"
}
```

エラーコードは RFC 6750（OAuth 2.0 Bearer Token Usage）の語彙に揃えることを推奨する。

| 状況 | HTTP | `error` |
|---|---|---|
| トークンが存在しない・失効済み | 401 | `invalid_token` |
| トークンの有効期限切れ | 401 | `invalid_token` |
| パススコープ外へのアクセス（R7） | 403 | `insufficient_scope` |
| レート制限超過（R8） | 429 | — |

**セッション Cookie を発行しないこと**。トークン認証はステートレスであるべきで、
副作用として Cookie を返すと API クライアント側で不要な状態管理が発生する。

### R4. トークン発行・失効の Web UI

既存の `/settings/security` 配下に「API トークン」セクションを追加する。
Phase Me で導入された安定URL規約に従い、`/me/tokens` を公開URLとして割り当てることを推奨する。

| 公開URL（安定） | リダイレクト先（内部実装） | 用途 |
|---|---|---|
| `GET /me/tokens` | `302 → /settings/security/tokens` | トークン一覧・発行 |

#### 画面要件

```
┌──────────────────────────────────────────────────┐
│  API トークン                                     │
├──────────────────────────────────────────────────┤
│  名前              最終利用      作成日            │
│  ─────────────────────────────────────────────  │
│  Alice の MacBook  2026/08/31   2026/08/01  [失効] │
│  Alice の Windows  未使用       2026/08/15  [失効] │
├──────────────────────────────────────────────────┤
│  [ + 新しいトークンを発行 ]                        │
└──────────────────────────────────────────────────┘
```

#### 発行時の表示要件

**平文トークンは発行直後の1回のみ表示し、以後は二度と表示しない。**
DB にはハッシュしか保存しないため、技術的にも再表示は不可能である。

```
┌──────────────────────────────────────────────────┐
│  トークンを発行しました                            │
│                                                  │
│  apx_kJ8xQ2mN7pR4tY6wZ1aB3cD5eF9gH0iL2nO4qS6uV8x │
│                                    [コピー]       │
│                                                  │
│  ⚠ この画面を閉じると二度と表示できません。         │
│    今すぐコピーして安全な場所に保管してください。    │
└──────────────────────────────────────────────────┘
```

#### API エンドポイント

| メソッド | パス | 説明 |
|---|---|---|
| `GET` | `/api/tokens` | 自分のトークン一覧（ハッシュは返さない） |
| `POST` | `/api/tokens` | 新規発行。**レスポンスにのみ平文を含む** |
| `DELETE` | `/api/tokens/{id}` | 失効（`revoked_at` を設定） |

これらは**セッション認証下でのみ**アクセス可能とすること。
トークン認証でトークンを発行できると、権限昇格の連鎖が起きうるため。

### R5. `X-Auth-Method` ヘッダー

上流サービスが認証方式を区別できるよう、ヘッダーを追加する。

既存のヘッダー一覧への追加提案：

| ヘッダー名 | 内容 | 例 |
|---|---|---|
| `X-Auth-Method` | 認証方式 | `session` / `token` / `guest` |
| `X-Auth-Token-Name` | トークン認証時のみ。トークンの識別名 | `Alice の MacBook` |

**用途の例**: timetrack では「Web の管理画面はセッション認証のみ許可し、
同期APIはトークン認証のみ許可する」といった制御を上流側で行いたい。
ヘッダーがないとこの区別ができない。

`X-Auth-Token-Name` はユーザー入力値であるため、
**ヘッダー値として安全な文字にサニタイズすること**（改行・制御文字の除去）。
ヘッダーインジェクションを防ぐため必須である。

### R6. ペアリングコード方式（推奨）

#### 動機

トークン文字列（50文字程度）を手作業でアプリにコピー&ペーストさせるのは、
特に別マシンで発行した場合に体験が悪い。

短いコードで端末を登録できると、以下のような導線が実現できる。

```mermaid
sequenceDiagram
    participant B as ブラウザ
    participant AP as auth-proxy
    participant D as デスクトップアプリ

    B->>AP: POST /api/pairing/codes
    AP-->>B: {code:"ABCD-1234", expires_in:600}
    Note over B: 画面に大きく "ABCD-1234" と表示

    Note over D: ユーザーが 8文字を手入力
    D->>AP: POST /api/pairing/claim<br/>{code:"ABCD-1234", device_name:"MacBook"}
    AP->>AP: コードを検証・ワンタイム消費
    AP-->>D: {token:"apx_xxx...", user_id:42}
    Note over D: OS のセキュアストレージに保存
```

#### テーブル

```sql
CREATE TABLE pairing_codes (
    code        TEXT    PRIMARY KEY,   -- "ABCD-1234" 形式
    user_id     INTEGER NOT NULL,
    expires_at  TEXT    NOT NULL,      -- 発行から10分程度
    used_at     TEXT,                  -- 使用済みの場合に設定（ワンタイム）
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

#### セキュリティ要件

コードが短い（8文字）ため、総当たり攻撃への対策が必須である。

- **文字種から紛らわしい文字を除外する**: `0/O`、`1/I/l` を除いた
  32文字（`ABCDEFGHJKLMNPQRSTUVWXYZ23456789`）を推奨。
  8文字で 32^8 ≒ 1.1兆通りの空間が確保できる
- **有効期限を短くする**: 10分程度
- **ワンタイム**: 一度使用したコードは即座に無効化する
- **claim エンドポイントに厳格なレート制限**: 同一 IP から毎分数回まで。
  試行失敗が一定回数を超えたらそのコードを無効化する
- **claim は未認証で叩けるエンドポイント**であることを認識し、
  タイミング攻撃対策（コードが存在しない場合も同じ処理時間にする）を行う

### R7. トークンのパススコープ制限（推奨）

ゲストトークンの `path_prefix` と同じ考え方で、API トークンにもスコープを設ける。

```
トークン発行時に path_prefix = "/sync/" を指定
  → そのトークンでは /sync/* 配下にしかアクセスできない
  → /admin/* にアクセスすると 403 insufficient_scope
```

**動機**: デスクトップアプリのトークンが漏洩した場合でも、
管理画面や他のパスへのアクセスを防げる。最小権限の原則に沿う。

timetrack のユースケースでは `/sync/` に限定したトークンを発行したい。

### R8. レート制限（推奨）

トークン単位でのリクエスト頻度制限。

| 対象 | 推奨値 |
|---|---|
| 通常の API リクエスト | 1トークンあたり 600 req/分 程度 |
| `/api/pairing/claim` | 1 IP あたり 5 req/分 程度（厳格に） |
| `POST /api/tokens` | 1ユーザーあたり 10 req/時 程度 |

実装は既存のブルートフォース対策（ログイン失敗時の遅延）と同様、
メモリ上のカウンタで十分と考える。永続化は不要。

### R9. CLI サブコマンド（任意）

既存の `auth-proxy list` と同様の運用コマンド。

```bash
auth-proxy token list [--user <username>]   # トークン一覧
auth-proxy token revoke <id>                # 失効
auth-proxy token create --user <username> --name <name> [--path-prefix /sync/]
```

`token create` は初期セットアップの自動化や、
ブラウザにアクセスできない環境での運用に有用である。

### R10. 管理画面でのトークン可視化（任意）

管理者が `/admin/` から全ユーザーのトークン発行状況を確認でき、
必要に応じて失効できる機能。

**動機**: 退職者のトークンを確実に失効させる運用が必要になる。
（ユーザー削除時は `ON DELETE CASCADE` で消えるが、
アカウントを残したまま端末だけ回収するケースがある）

---

## 6. 環境変数の追加提案

既存の命名規約（`AUTH_PROXY_` プレフィックス）に従う。

```dotenv
# API トークン機能の有効化。デフォルト false（後方互換のため）
AUTH_PROXY_API_TOKEN_ENABLED=true

# 発行するトークンのデフォルト有効期限（日数）。0 または未設定で無期限
AUTH_PROXY_API_TOKEN_DEFAULT_TTL_DAYS=0

# ペアリングコードの有効期限（分）。デフォルト 10
AUTH_PROXY_PAIRING_CODE_TTL_MINUTES=10

# トークンあたりのレート制限（リクエスト/分）。デフォルト 600
AUTH_PROXY_API_TOKEN_RATE_LIMIT=600
```

**デフォルトを `false` にする理由**: 既存の auth-proxy 利用者にとって、
アップデートで認証経路が増えることは予期しない挙動変更になる。
明示的にオプトインさせるべきである。

---

## 7. セキュリティ上の考慮事項

既存の「セキュリティ設計」セクションへの追記提案。

### 7.1 X-Auth-* ヘッダーの偽装防止（既存機能との関係）

既存の「クライアントから送信された `X-Auth-` で始まるヘッダーは上流転送前に必ず除去する」
という処理は、**トークン認証経路でも同一に適用されなければならない**。

トークン認証のミドルウェアがこの除去処理より前に実行されると、
`Authorization: Bearer` と同時に `X-Auth-Role: admin` を送ることで
権限昇格が可能になる。**処理順序を明示的にテストすること**。

### 7.2 トークンのログ出力禁止

`RUST_LOG=debug` 等でトークンが平文でログに出力されないよう、
`Authorization` ヘッダーはログからマスクすること。

```
# 悪い例
DEBUG request headers: {"authorization": "Bearer apx_kJ8xQ2..."}

# 良い例
DEBUG request headers: {"authorization": "Bearer apx_***"}
```

### 7.3 トークン比較のタイミング攻撃

`token_hash` の照合は DB のインデックス検索で行われるため、
文字列比較のタイミング攻撃は成立しにくい。
ただしメモリ上で比較する実装にする場合は、定数時間比較を使用すること。

### 7.4 HTTPS の強制

トークンは Bearer 方式であり、平文で送信されると盗聴される。
auth-proxy は TLS 終端を Traefik 等に委譲する設計であるため、
**ドキュメント上で「API トークン利用時は TLS 必須」と明記すべきである**。

---

## 8. 後方互換性

本提案はすべて**追加のみ**であり、既存の挙動を変更しない。

| 既存機能 | 影響 |
|---|---|
| セッション Cookie 認証 | 影響なし。`Authorization` ヘッダーがない場合は従来通り |
| ゲストトークン | 影響なし |
| `X-Auth-*` ヘッダー | `X-Auth-Method` が追加されるのみ。既存ヘッダーの値は不変 |
| 静的ファイルモード | 影響なし（トークン認証も同様に動作させることは可能） |
| 既存の DB スキーマ | テーブル追加のみ。既存テーブルへの変更なし |

`AUTH_PROXY_API_TOKEN_ENABLED=false`（デフォルト）の場合、
`Authorization: Bearer` は無視され、完全に従来通りの挙動となる。

---

## 9. テスト観点の提案

以下は実装時に必ず確認いただきたい項目である。

```
【認証の基本動作】
- 有効なトークンで上流に到達し、正しい X-Auth-User-Id が付与される
- 失効済みトークンで 401 が返る
- 期限切れトークンで 401 が返る
- 存在しないトークンで 401 が返る
- Authorization ヘッダーが Bearer 形式でない場合、セッション認証にフォールバックする

【エラー応答形式】
- Bearer 付きリクエストの失敗時、302 ではなく 401 が返る
- レスポンスが JSON である
- WWW-Authenticate ヘッダーが付与される
- トークン認証成功時に Set-Cookie が返らない

【権限昇格の防止】★最重要
- Authorization: Bearer と X-Auth-Role: admin を同時に送っても、
  上流には正しいロールが渡る（クライアント由来ヘッダーが除去される）
- 一般ユーザーのトークンで /admin/* にアクセスすると 403
- トークン認証で POST /api/tokens を叩けない（セッション認証必須）

【パススコープ（R7）】
- path_prefix=/sync/ のトークンで /sync/v1/logs にアクセスできる
- 同トークンで /admin/ にアクセスすると 403 insufficient_scope

【ペアリング（R6）】
- 有効なコードでトークンが取得できる
- 使用済みコードで再度 claim すると失敗する
- 期限切れコードで失敗する
- 存在しないコードでも、存在するコードと同等の応答時間になる

【トークン発行 UI（R4）】
- 平文トークンが発行レスポンスにのみ含まれ、一覧APIには含まれない
- 他ユーザーのトークンを失効できない
```

---

## 10. 実装フェーズの提案

auth-proxy 側のロードマップに合わせて分割可能な形で提案する。

| フェーズ | 内容 | timetrack 側のブロッカー解消 |
|---|---|---|
| **Phase API-1** | R1・R2・R3・R5（Bearer 認証の中核） | **これで同期APIが実装可能になる** |
| Phase API-2 | R4（Web UI での発行・失効） | 運用可能になる |
| Phase API-3 | R6・R7（ペアリングコード・パススコープ） | 体験と安全性が向上する |
| Phase API-4 | R8・R9・R10（レート制限・CLI・管理画面） | 運用が成熟する |

timetrack 側は **Phase API-1 の完了をもって実装を開始できる**。
それまでは開発環境でトークンを DB に直接 INSERT して検証を進める想定である。

---

## 11. timetrack 側の対応（参考情報）

auth-proxy 側の実装判断の参考として、上流側がどう使うかを記載する。

### リクエスト例

```http
POST /sync/v1/logs HTTP/1.1
Host: timetrack.example.com
Authorization: Bearer apx_kJ8xQ2mN7pR4tY6wZ1aB3cD5eF9gH0iL2nO4qS6uV8x
Content-Type: application/json

{"device_id":"01931f...","logs":[...]}
```

### timetrack が期待する上流への転送内容

```http
POST /sync/v1/logs HTTP/1.1
Host: timetrack:3000
X-Auth-User: alice
X-Auth-User-Id: 42
X-Auth-Role: user
X-Auth-Method: token
X-Auth-Token-Name: Alice の MacBook
X-Auth-Issuer: auth-proxy
Content-Type: application/json

{"device_id":"01931f...","logs":[...]}
```

timetrack は `X-Auth-User-Id` からユーザーを特定し、
`X-Auth-Method: token` であることを確認して同期APIの処理を行う。
**timetrack 側に認証コードは一切入らない。**

### ネットワーク構成（変更なし）

```
[Traefik] → [auth-proxy :8080] → [timetrack :3000]
                                   ports: を持たない
                                   internal: true ネットワークのみ
```

本提案が実現すれば、v10 仕様書の Docker Compose 構成をそのまま維持できる。

---

## 12. 想定される議論点

提案側として認識している論点を先に挙げておく。

### 12.1 auth-proxy のスコープが広がりすぎないか

auth-proxy は「認証に特化」する設計思想を持つ。
API トークン認証は**認証方式の追加**であり、スコープ内と考える。
（TLS 終端やルーティングのような、他ミドルウェアの責務を取り込む話ではない）

### 12.2 OAuth 2.0 / OIDC を実装すべきではないか

将来的な選択肢としてはあり得るが、現時点では過剰である。

- OAuth 2.0 の完全実装は認可サーバーとしての責務を負うことになり、
  「単一バイナリ・外部サービス不要」という設計思想と緊張関係にある
- 今回必要なのは「長期有効なトークンでの認証」のみであり、
  第三者アプリへの権限委譲（OAuth の本来の目的）は不要

ただし**エラー応答の語彙（RFC 6750）だけは OAuth に揃えておく**ことで、
将来 OIDC に発展させる場合の互換性を確保できる。

### 12.3 Argon2 ではなく SHA-256 でよいのか

5.R1 に記載の通り、エントロピーの観点から SHA-256 が適切と考える。
この判断について異論があれば議論したい。

---

## 13. まとめ

| 項目 | 内容 |
|---|---|
| **提案の本質** | auth-proxy の「上流サービスの認証負担ゼロ」という価値を、ブラウザ以外のクライアントにも拡張する |
| **最小実装** | Phase API-1（R1・R2・R3・R5） |
| **後方互換性** | 完全に保たれる（環境変数でオプトイン） |
| **代替案** | 上流をバイパスする構成が可能だが、auth-proxy の中核的なセキュリティモデルが崩れるため非推奨 |

ご検討のほどよろしくお願いいたします。
不明点・懸念点があればご指摘ください。
