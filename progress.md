# Phase 3a-2 実装進捗

## ✅ 完了

### Step 1: UserRow に totp_enabled フィールド追加
- UserRow 構造体に `pub totp_enabled: i32` フィールド追加
- get_by_username()、get_by_id()、list_all() の SQLクエリで totp_enabled を取得するよう修正
- ビルド成功（warnings 0）
- テスト全合格（49/49）

### Step 2: handlers/admin/users.rs の変更 ✅
- GET /admin/users テーブルにMFA列追加（🔐 or —）
- GET /admin/users/:id/disable-mfa 実装（確認フォーム、Tailwind CSS）
- POST /admin/users/:id/disable-mfa 実装（MFA無効化、管理者パスワード確認）
- DisableMfaForm 構造体作成
- spawn_blocking でタイミング攻撃対策（500ms遅延）
- ビルド成功、テスト全合格（49/49）

### Step 3: handlers/settings/ ディレクトリ構成変更 ✅
- settings.rs → settings/mod.rs に移動完了
- settings/security.rs 新規作成
- pub mod security; 追加
- ビルド成功

### Step 4: settings/security.rs の実装 ✅
- ChangePasswordForm 構造体作成
- RegenerateBackupCodesForm 構造体作成
- show() - GET /settings/security（セキュリティ設定ページ）
  - MFA有効/無効で異なるUIを表示
  - バックアップコード残数表示
- show_password() - GET /settings/security/password（パスワード変更フォーム）
- handle_password() - POST /settings/security/password（パスワード変更処理）
  - 現在のパスワード検証（spawn_blocking）
  - 新パスワード8文字以上チェック
  - 確認パスワード一致チェック
  - タイミング攻撃対策（500ms遅延）
- show_regenerate_backup_codes() - GET /settings/security/mfa/backup-codes/regenerate
- handle_regenerate_backup_codes() - POST /settings/security/mfa/backup-codes/regenerate
  - 現在のパスワード検証
  - 新しいバックアップコード生成
  - 平文8本表示（一度限り）
- Tailwind CSS スタイル実装
- ビルド成功、テスト全合格（49/49）

### Step 5: mfa.rs へ backup_code_count() メソッド追加 ✅
- `pub async fn backup_code_count(&self, user_id: i64) -> Result<i64>`
- 未使用バックアップコード件数を返す
- ビルド成功

### Step 6: router.rs の変更 ✅
- /admin/users/:id/disable-mfa ルート追加
- /settings/security/* ルート追加
  - GET /settings/security
  - GET /settings/security/password
  - POST /settings/security/password
  - GET /settings/security/mfa/backup-codes/regenerate
  - POST /settings/security/mfa/backup-codes/regenerate
  - POST /settings/security/mfa/* (既存ハンドラー流用)
- /settings/mfa ルート（後方互換）
- handlers/admin/mod.rs に show_disable_mfa・handle_disable_mfa を追加

### Step 7: 環境変数接頭語の統一 ✅
環境変数の接頭語を `APP_*` から `AUTH_PROXY_*` に統一（仕様変更に対応）

**変更対象の環境変数:**
- `APP_UPSTREAM_URL` → `AUTH_PROXY_UPSTREAM_APP_URL`
- `APP_SERVE_PATH` → `AUTH_PROXY_SERVE_PATH`
- `APP_DB_PATH` → `AUTH_PROXY_DB_PATH`
- `APP_LISTEN_ADDR` → `AUTH_PROXY_LISTEN_ADDR`
- `APP_SESSION_TTL_HOURS` → `AUTH_PROXY_SESSION_TTL_HOURS`
- `APP_ISSUER_NAME` → `AUTH_PROXY_ISSUER_NAME`
- `APP_MFA_ENCRYPTION_KEY` → `AUTH_PROXY_MFA_ENCRYPTION_KEY`
- `APP_GUEST_TOKEN_SECRET` → `AUTH_PROXY_GUEST_TOKEN_SECRET`
- `APP_GUEST_TOKEN_API_KEY` → `AUTH_PROXY_GUEST_TOKEN_API_KEY`

**実装内容:**
- src/config.rs: 環境変数読み込みロジック更新（互換性のため旧名もフォールバック対応）
- src/handlers/settings/security.rs: APP_ISSUER_NAME → AUTH_PROXY_ISSUER_NAME に更新
- .env.auth-proxy: 全環境変数を新形式に更新
- .env.auth-proxy.example: ドキュメント含め全環境変数を新形式に更新
- ビルド成功（warnings 0）✅
- コンパイル検証完了 ✅

### Step 8: Docker ホスト側ポートの可変化 ✅
docker-compose のホスト側バインドポートを環境変数化し、デプロイ時に柔軟に設定可能に

**実装内容:**
- docker-compose.example.yml: `ports: - "127.0.0.1:${AUTH_PROXY_HOST_PORT:-8080}:8080"`
- docker-compose.yml: 同様に更新
- .env.auth-proxy.example: `AUTH_PROXY_HOST_PORT` についてのドキュメント追加
- README.md:
  - Step 2 のdocker-compose.yml 説明を更新
  - Step 3 のポート設定についての説明を追加
  - 環境変数リファレンスに `AUTH_PROXY_HOST_PORT` を追加
  - ポート設定についての詳細説明を追加
- ビルド検証済み ✅

## テスト状況
- 全テスト合格: **49/49** ✅
- ビルド成功（warnings 0）✅
- cargo check: success ✅
- 環境変数リファクタリング後: cargo check success ✅

## 注記
- インストラクションソース: phase3a2-agent-instructions.md
- UIについて改良済み（Tailwind CSS使用）
- 確認フォーム：管理者パスワード入力必須
- バリデーション：新パスワード8文字以上、確認パスワード一致確認
- spawn_blocking によるタイミング攻撃対策（500ms遅延）

## 実装の概要
Phase 3a-2 は以下の機能を追加しました：
1. **管理者視点**: ユーザーのMFA強制無効化機能（管理者パスワード確認付き）
2. **ユーザー視点**: セキュリティ設定の一元化ページ (/settings/security)
3. **パスワード管理**: ユーザー自身によるパスワード変更機能
4. **バックアップコード**: 再発行機能（パスワード確認必須）
5. **UI改良**: Tailwind CSS による統一的なUI設計

## 次ステップ
- 実装指示書の環境変数記載部分を新形式に更新（internal/ フォルダ内の仕様書）
- SESSION1_SUMMARY.md 等の旧環境変数参照をアップデート
- README_ja.md も新形式に合わせて更新（古いドキュメント）

## 次フェーズの推奨事項
- Phase 3b: 追加のMFA方式対応（メール認証、SMS等）
- Phase 4: デバイス信頼チェーンの強化
- テストカバレッジの拡大（UI統合テスト）
