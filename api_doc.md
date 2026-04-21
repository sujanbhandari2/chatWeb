# Vitafy Chat Backend — API Reference

Base URL defaults to `http://localhost:4040` (see `PORT` and `HOST` in `.env`). All JSON bodies use `Content-Type: application/json` unless noted.

**Global HTTP prefix:** `api`  
**URI versioning:** `v1` (Nest default version). Versioned routes use the segment **`/v1/`** immediately after `api` (e.g. `/api/v1/chat/...`, `/api/v1/system/health`).  

Example: `GET http://localhost:4040/api/v1/system/health`

Interactive OpenAPI (non-production): `http://localhost:4040/api/docs/admin`, `/api/docs/tenant`, `/api/docs/chat` (see `main.ts` / `swagger.bootstrap.ts`).

---

## Conventions

- **CORS:** Configured via `FRONTEND_ORIGIN` (default `http://localhost:5173`). Allowed methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`. Allowed headers include `Content-Type`, `Authorization`, `X-Api-Key`, `X-Access-Key`, `X-Signature`, `X-Timestamp`. Credentials enabled.

- **Success envelope:** Every successful HTTP response body is wrapped by `TransformInterceptor`:

```json
{ "success": true, "data": <handler return value> }
```

- **Error envelope:** `HttpExceptionFilter` returns:

```json
{ "success": false, "error": "<string or string[]>" }
```

---

## Authentication (HTTP)

### Admin routes (`/api/v1/admin/...`)

Use:

```http
Authorization: Bearer <jwt>
```

Obtain JWT with `POST /api/v1/admin/login`. Payload shape: `{ typ: "admin", sub: "<id>", email: "<email>" }`. Expiry: `JWT_EXPIRES_IN` (default `15m`).

### Tenant routes (`/api/v1/shared/...`)

Same `Authorization: Bearer <jwt>` header. Obtain JWT with `POST /api/v1/auth/tenant/login`. Payload: `{ typ: "tenant", sub: "<id>", email: "<email>" }`. The `sub` is the **tenant** id (`Tenant.id`, bigint in DB, serialized as string in JSON).

### Chat routes (REST under `/api/v1/chat/...`)

`ApiKeyGuard` authenticates with **`X-Api-Key: <accessKey>:<secretKey>`** (colon-separated in one header). Invalid or missing credentials return **401**.

**Mounting:** `ChatModule` is imported by **`SocketModule`** (see `src/app/app.module.ts`, `src/modules/socket/socket.module.ts`) as well as by **`RoutesUserModule`** (`src/router/routes/routes.user.module.ts`). Nest registers the chat HTTP controllers once at controller path **`chat`**, so in this app they are reachable at **`/api/v1/chat/...`** (global prefix `api`, URI version `v1`), not under `/api/v1/users/...`.

### Tenant scope (chat)

Chat routes are scoped by the **API key’s tenant** (`request.userId` from the key row). There is no separate company header.

### Presigned uploads (`/api/upload`)

Same **`X-Api-Key: accessKey:secretKey`** as chat. This route is **version-neutral**: it is **`POST /api/upload`**, not under `/api/v1/…`.

Use it to obtain a **presigned S3 PUT URL** and the final **`fileUrl`** (HTTPS) to pass in chat message `attachments[].url` after the browser uploads the file directly to object storage.

**Configuration (server):** `AWS_BUCKET`, `AWS_REGION`, `AWS_BASE_URL` (public origin of objects, no trailing slash — must match where your bucket is served, e.g. CDN or `https://bucket.s3…amazonaws.com`), optional `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (omit on AWS if the instance uses an IAM role), optional `UPLOAD_DIR` (default `chat_test`), optional `PRESIGN_UPLOAD_EXPIRES_SECONDS` (default **900**, clamped **60–86400**).

---

## Upload — `POST /api/upload`

**Auth:** `X-Api-Key` (tenant-scoped; object keys include the tenant id).

**201** (Nest default for `POST`) — `data`:

| Field | Type | Description |
|--------|------|-------------|
| `method` | `"PUT"` | HTTP method for the upload request |
| `uploadUrl` | string | Presigned URL (query string contains auth; short-lived) |
| `fileUrl` | string | Public HTTPS URL of the object after upload — use this value in **`attachments[].url`** |
| `key` | string | Object key in the bucket |
| `headers` | object | Headers the client **must** send on the PUT (at minimum **`Content-Type`**, must match the `mimeType` you sent when presigning) |
| `expiresIn` | number | TTL of `uploadUrl` in seconds |

**Body**

| Field | Type | Rules |
|--------|------|--------|
| `fileName` | string | Required; path segments stripped; sanitized to a safe file segment |
| `mimeType` | string | Optional; default `application/octet-stream`; sent as `Content-Type` on PUT |
| `byteSize` | integer | Optional; informational only |
| `prefix` | string | Optional; extra path segment under the tenant folder (`[a-zA-Z0-9_-]{1,64}`) |

**503** — Missing `AWS_BUCKET` / `AWS_REGION`, or missing `AWS_BASE_URL`, or credentials cannot sign (misconfiguration).

### Frontend flow

1. `POST /api/upload` with JSON `{ "fileName": "photo.jpg", "mimeType": "image/jpeg" }` and header `X-Api-Key: accessKey:secretKey`.
2. From `data`, take **`uploadUrl`**, **`headers`**, and **`method`** (`PUT`).
3. **`fetch(uploadUrl, { method: 'PUT', headers: data.headers, body: fileBlob })`** — use the **File** / **Blob** as body; do not send JSON.
4. On success, send the message with **`data.fileUrl`** in `attachments[].url` (see **POST `/api/v1/chat/conversations/:conversationId/messages`** below).

---

## System

### `GET /api/v1/system/health`

No authentication.

**200** — inside success envelope, `data` is:

```json
{ "status": "ok" }
```

---

## Auth — `/api/v1/auth`

### `POST /api/v1/auth/tenant/login`

Authenticates a **tenant** account (email + password).

**Body**

| Field | Type | Rules |
|--------|------|--------|
| `email` | string | Valid email |
| `password` | string | Min length 8 |

**201** (Nest default for `POST`) — `data`:

```json
{
  "token": "<jwt>",
  "id": "<tenant id>",
  "email": "<string>",
  "name": "<string>",
  "settings": {
    "imageUpload": true,
    "audioAttachmentUpload": true,
    "voiceRecording": true,
    "createGroup": true,
    "editGroup": true,
    "chatListSearch": true,
    "translateMessages": true,
    "voiceTranscription": true,
    "messageReactions": true,
    "deleteConversation": true
  }
}
```

`settings` is always returned as the full [tenant feature flag](#tenant-settings-feature-flags) object (missing DB keys default to `true`). Shape is defined in code as `TenantFeatureSettings` in `src/modules/tenants/tenant.constants.ts` (`mergeTenantFeatureSettings`, `DEFAULT_TENANT_SETTINGS`).

**401** — Unknown email or bad password (`Invalid credentials`).

### Tenant `settings` (feature flags)

Stored on `Tenant.settings` as JSON (`jsonb`-backed in PostgreSQL). **Admin** `POST /api/v1/admin/tenants` persists `DEFAULT_TENANT_SETTINGS` for new tenants (all flags **`true`**). **Login** and **shared/me** merge stored JSON with defaults so every response includes all keys.

| Key | Meaning |
|-----|--------|
| `imageUpload` | Allow image uploads in chat |
| `audioAttachmentUpload` | Allow audio file attachments |
| `voiceRecording` | Allow voice recording |
| `createGroup` | Allow creating group conversations |
| `editGroup` | Allow editing group metadata |
| `chatListSearch` | Enable chat list search |
| `translateMessages` | Enable message translation (when server supports it) |
| `voiceTranscription` | Enable voice / audio transcription |
| `messageReactions` | Enable message reactions |
| `deleteConversation` | Allow deleting conversations |

**Note:** Flags are exposed to clients; enforcement in chat routes is not wired in this backend yet—add guards if tenants should be restricted server-side.

---

## Admin — `/api/v1/admin`

### `POST /api/v1/admin/login`

**Body:** `email`, `password` (same rules as tenant login).

**201** — `data`:

```json
{
  "token": "<jwt>",
  "id": "<admin id>",
  "email": "<string>",
  "name": "<string>"
}
```

### `GET /api/v1/admin/me`

Requires admin Bearer JWT.

**200** — `data`: `{ "id", "email", "name", "createdAt" }`.

### Tenants CRUD — `/api/v1/admin/tenants`

All require admin Bearer JWT.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/tenants` | List active tenants |
| `POST` | `/api/v1/admin/tenants` | Create tenant account |
| `PATCH` | `/api/v1/admin/tenants/:id` | Update tenant (`id` = `Tenant.id`) |
| `DELETE` | `/api/v1/admin/tenants/:id` | Soft-delete tenant |

**Create body**

| Field | Type | Rules |
|--------|------|--------|
| `name` | string | Max 200 |
| `email` | string | Email |
| `password` | string | Min 8 |

**Update body** (all optional): `name`, `email`, `password` (same constraints when present).

**Create 201** — public tenant shape: `id`, `email`, `name`, `settings`, `createdAt`. `settings` is the merged [tenant feature flags](#tenant-settings-feature-flags) object (same as tenant login).

**Update 200** — same public tenant shape as create.

**List 200** — `data`: array of public tenant shapes (same fields as create/update).

**Example** — create tenant response `data.settings` (all `true` by default):

```json
{
  "imageUpload": true,
  "audioAttachmentUpload": true,
  "voiceRecording": true,
  "createGroup": true,
  "editGroup": true,
  "chatListSearch": true,
  "translateMessages": true,
  "voiceTranscription": true,
  "messageReactions": true,
  "deleteConversation": true
}
```

**Delete 200** — `data`: `{ "deleted": true }`.

**409** — Duplicate tenant email on create/update (`Tenant email already exists`).

### Admin API keys — `/api/v1/admin/tenants/:userId/api-keys`

`:userId` is the **tenant** id (`Tenant.id`). Admin Bearer JWT required.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/tenants/:userId/api-keys` | List keys (no secrets) |
| `POST` | `/api/v1/admin/tenants/:userId/api-keys` | Create key; **secret returned once** in `data` |
| `POST` | `/api/v1/admin/tenants/:userId/api-keys/:id/revoke` | Revoke key |

**Create body (optional):** `name`, `scopes` (string array), `expiresAt` (ISO date string).

**HTTP:** `POST` create and `POST` …`/revoke` return **201** (Nest default for `POST`). `GET` list returns **200**.

---

## Shared (tenant JWT) — `/api/v1/shared`

### `GET /api/v1/shared/me`

Tenant Bearer JWT + tenant-only guard.

**200** — `data`: `{ id, email, name, settings, createdAt }`. `settings` uses the same [tenant feature flags](#tenant-settings-feature-flags) shape as tenant login (merged defaults).

**Example** — `data` (abbreviated):

```json
{
  "id": "1",
  "email": "tenant@example.com",
  "name": "Acme",
  "settings": {
    "imageUpload": true,
    "audioAttachmentUpload": true,
    "voiceRecording": true,
    "createGroup": true,
    "editGroup": true,
    "chatListSearch": true,
    "translateMessages": true,
    "voiceTranscription": true,
    "messageReactions": true,
    "deleteConversation": true
  },
  "createdAt": "2026-01-01T00:00:00.000Z"
}
```

### API keys (own keys) — `/api/v1/shared/api-keys`

Tenant Bearer JWT required.

| Method | Path |
|--------|------|
| `GET` | `/api/v1/shared/api-keys` |
| `POST` | `/api/v1/shared/api-keys` |
| `POST` | `/api/v1/shared/api-keys/:id/revoke` |

Same DTOs and semantics as admin key routes; `:id` is the API key row id.

**HTTP:** `GET` **200**; `POST` create and `POST` …`/revoke` **201**.

---

## Chat — REST — `/api/v1/chat`

All routes use `ApiKeyGuard`; tenant scope always comes from the **API key** (see **Chat routes** under [Authentication (HTTP)](#authentication-http)).

### `GET /api/v1/chat/tenant`

Returns the tenant id resolved from the current API key.

**200** — `data`: `{ "tenantId": "<bigint string>" }`.

### `POST /api/v1/chat/users`

Registers a **ChatUser** for this tenant (**get-or-create**). If a user already exists for this tenant with the same `(providerId, providerUserId)`, that row is returned. Otherwise, if one exists with the same normalized `email`, that row is returned. Otherwise a new row is created. Lookup order is external identity first, then email.

**Body**

| Field | Type | Rules |
|--------|------|--------|
| `providerId` | string | Provider or source key (stored as `provider_id`), max 128 |
| `providerUserId` | string | User id from that provider (stored as `provider_user_id`), max 512 |
| `email` | string | Email (normalized to lowercase); used for the email match |
| `name` | string | Optional display name; max 200. If omitted, the server uses the normalized **email** as the display name on **create** only (reused rows are unchanged). |

**201** — `ChatUser` row (Prisma shape: `id`, `tenantId`, `providerId`, `providerUserId`, `email`, `name`, `status`, timestamps). May be an existing row when the request matched a prior registration.

### `GET /api/v1/chat/users`

Lists all chat users for this tenant, newest first.

**200** — `data`: array of `ChatUser` rows for the tenant.

### `POST /api/v1/chat/conversations`

**Body (optional fields)**

| Field | Type | Description |
|--------|------|-------------|
| `type` | enum | Optional. `DIRECT` (default), `GROUP`, or `SUPPORT`. |
| `creatorUserId` | numeric string | **Required** when `type` is `GROUP`. That chat user is added as participant with **ADMIN** role. |
| `participantIds` | numeric string[] | **GROUP:** extra members besides `creatorUserId`. **DIRECT / SUPPORT:** optional initial participants (all `MEMBER`); omit for an empty thread and add people with `POST /api/v1/chat/conversations/:conversationId/participants`. |

**400** — e.g. missing `creatorUserId` for group, or invalid/inactive users.

**201** — conversation with `participants`: each item includes participant `role` (`MEMBER` or `ADMIN`) and nested `chatUser` (`id`, `providerId`, `providerUserId`, `name`, `email`, `status`).

### `GET /api/v1/chat/conversations`

**Query**

| Param | Type | Description |
|--------|------|-------------|
| `forUserId` | numeric string | If set, only conversations that chat user participates in (must belong to this tenant). |

If omitted, returns all conversations for this tenant. Ordered by `createdAt` descending.

**403** — `forUserId` is not an active chat user in this tenant.

### `POST /api/v1/chat/conversations/:conversationId/participants`

**Body**

| Field | Type | Rules |
|--------|------|--------|
| `userId` | numeric string | Chat user to add |
| `actorUserId` | numeric string | **Required** for group chats: must be a participant with **ADMIN** role. |

**201** — participant row with nested `chatUser` (same selected fields as in conversation payloads).

**403** — Not a group admin when required.

**409** — User already a participant.

### `GET /api/v1/chat/conversations/:conversationId/messages`

**Query:** `page` (default 1, min 1), `pageSize` (default 20, 1–100).

**200** — `data` object (not a separate `pagination` key):

```json
{
  "items": [],
  "page": 1,
  "pageSize": 20,
  "total": 0
}
```

Messages are ordered **newest first** (`createdAt` desc). Soft-deleted messages are omitted. Each item is a serialized message (same shape as `POST .../messages` returns):

| Field | Notes |
|--------|--------|
| `id`, `conversationId`, `tenantId`, `senderId`, `type`, `content`, `createdAt`, `deletedAt` | `content` is plain text, caption for uploads, or a single legacy HTTPS URL. Older rows may still store a **JSON media envelope** in `content`; see `attachments` column below. |
| `attachments` | **Optional.** Array read from PostgreSQL **`jsonb`** on `messages.attachments`. Each item: `{ "fileUrl", "size"?, "fileType"?, "fileName"?, "mimeType"?, "kind"? }` (`kind`: client hint such as `live_recording`, `camera`, `upload`). Omitted in JSON when empty. For legacy envelope-only rows (no column data), the API still returns this array derived from `content` when it parses as a v1 envelope. |
| `replyToMessageId` | **Optional.** Numeric string when this message replies to another message in the same conversation (`messages.reply_to_message_id`). |
| `replyTo` | **Optional.** Snapshot of the parent message when loaded: `{ id, senderId, type, content, createdAt, sender?: { id, name } }`. Omitted if the parent row is missing (e.g. cleared after parent delete). |
| `reactions` | **Optional.** One row per chat user per message (upsert). Each item: `{ id, chatUserId, reactionType, userName }` (`userName` from `ChatUser.name`). Omitted when empty. |
| `translatedMessage`, `transcribedMessage` | Optional strings when AI endpoints have been used (see translate/transcribe below). |
| `sender` | `{ id, name }` when loaded |

There is **no** automatic signed `url` field; clients use **`attachments[].fileUrl`** (HTTPS URLs you supply, e.g. presigned object storage).

### `POST /api/v1/chat/conversations/:conversationId/messages`

**HTTP:** **201 Created** (Nest default for `POST`).

REST send (also broadcasts over Socket.IO to the conversation room). Request body is JSON (`Content-Type: application/json`). **Raw multipart file upload is not handled on this route**; upload binaries with your storage provider, then send **HTTPS** file URLs in `attachments`.

**Body**

| Field | Type | Rules |
|--------|------|--------|
| `senderId` | numeric string | Chat user id sending the message (must be participant, same tenant) |
| `type` | enum | `TEXT`, `IMAGE`, `VOICE`, `VIDEO`, `FILE`, `LINK`, `OTHER` (Prisma `MessageType`) |
| `content` | string | Optional if `attachments` is non-empty. Max 50000 chars. Plain text, caption for media, or a **single** legacy HTTPS media URL (e.g. voice file) when not using `attachments`. **Required** (non-empty after trim) when `attachments` is omitted or empty. |
| `attachments` | array | Optional. Up to **50** items in one request, in any order — images, videos, audio, documents, live recordings, etc. Allowed for **any** `MessageType` (often **`OTHER`** for mixed bundles). |
| `replyToMessageId` | numeric string | Optional. Must reference an existing, non-deleted message in **this** conversation (same tenant). Stored as `messages.reply_to_message_id`. |

**`attachments[]` item**

| Field | Type | Rules |
|--------|------|--------|
| `url` | string | Required on each item. **HTTPS only** (`https://...`), max 2048 chars (e.g. presigned GET URL). |
| `mimeType` | string | Optional, max 128 chars (e.g. `image/jpeg`, `video/mp4`, `audio/mp4`). |
| `fileName` | string | Optional, max 512 chars. |
| `byteSize` | integer | Optional, non-negative (uncompressed size if known). |
| `kind` | string | Optional, max 64 chars. Client-defined hint, e.g. `upload`, `live_recording`, `camera`, `screen`, `voice_note`. |

**Validation:** You must send at least one of: non-empty `content` (after trim), or one or more `attachments`. When `attachments` is present, **`content`** is stored as the **caption only** (may be empty), and each item is stored in **`messages.attachments`** as JSONB (see response shape below).

**Example** (request uses `url` / `byteSize`; response uses `fileUrl` / `size`):

```json
{
  "senderId": "1",
  "type": "IMAGE",
  "content": "See wound site",
  "attachments": [
    {
      "url": "https://cdn.example.com/tenant/msg/abc.jpg",
      "mimeType": "image/jpeg",
      "fileName": "photo.jpg",
      "byteSize": 245678
    }
  ]
}
```

**201** — **serialized** message (same shape as each element in `GET .../messages` → `data.items`). When files were sent, **`attachments`** mirrors the JSONB payload (`fileUrl`, optional `size`, `fileType`, `fileName`, `mimeType`, `kind`). Request field `url` is stored as `fileUrl`; `byteSize` as `size`.

**Database:** The `messages.attachments` column must exist as **`jsonb`** (nullable); **`messages.reply_to_message_id`** is an optional nullable FK for replies. Sync with `npx prisma migrate deploy` / `prisma migrate dev` after schema changes, or `npx prisma db push` in development. Without matching columns, creates fail at runtime.

**Example — mixed bundle** (`type` often `OTHER`; up to 50 items):

```json
{
  "senderId": "12",
  "type": "OTHER",
  "content": "Visit notes",
  "attachments": [
    { "url": "https://cdn.example.com/w.jpg", "mimeType": "image/jpeg", "kind": "camera" },
    { "url": "https://cdn.example.com/walk.m4a", "mimeType": "audio/mp4", "kind": "live_recording" },
    { "url": "https://files.example.com/lab.pdf", "mimeType": "application/pdf", "kind": "upload" }
  ]
}
```

**Socket parity:** The `send_message` socket payload is `{ conversationId, type, content, replyToMessageId? }`. Optional **`replyToMessageId`** matches REST (same validation). Socket sends do **not** populate `messages.attachments`; use REST for structured uploads, or mirror a legacy JSON envelope in `content` if you must use the socket only.

### `POST /api/v1/chat/conversations/:conversationId/messages/:messageId/reactions`

Upserts the calling tenant’s reaction for **`userId`** on **`messageId`**: at most **one** reaction row per `(messageId, chatUserId)`; a second POST with the same user **replaces** `reactionType`. Also broadcasts **`reaction_added`** on Socket.IO to the conversation room (same payload shape as below).

**Body**

| Field | Type | Rules |
|--------|------|--------|
| `userId` | numeric string | Chat user profile id performing the reaction (must be a participant) |
| `reactionType` | string | Non-empty after trim; max 128 chars (emoji or token, e.g. `thumbs_up`) |

**201** — Prisma **`MessageReaction`** row (`id`, `messageId`, `chatUserId`, `reactionType`, timestamps, …). BigInt fields serialize as strings in JSON.

**400** — Missing `reactionType`, invalid ids. **403** — Not a participant. **404** — Message not found or wrong conversation / tenant.

### `DELETE /api/v1/chat/conversations/:conversationId/messages/:messageId/reactions`

Removes **`userId`**’s reaction on that message, if any.

**Query (required)**

| Param | Type | Description |
|--------|------|-------------|
| `userId` | numeric string | Chat user whose reaction to remove |

**200** — `data`: `{ "removed": true }` if a row was deleted, or `{ "removed": false }` if there was no reaction. On successful delete, the server also emits **`reaction_removed`** on Socket.IO: `{ messageId, conversationId, userId }`.

**400** — Missing `userId` query parameter.

### `POST /api/v1/chat/conversations/:conversationId/messages/:messageId/translate`

**HTTP:** **200 OK** (not 201).

Runs English translation for the message (OpenAI). **Requires** `OPENAI_API_KEY` (and related config) on the server.

**Query (optional)**

| Param | Type | Description |
|--------|------|-------------|
| `force` | boolean | If truthy, recomputes translation even when `translatedMessage` is already set. Query accepts `true` / `false` or coerced values (`1`, string `"true"`). |

**200** — serialized message (same fields as list items), with `translatedMessage` populated or updated.

**400 / 404 / 503** — Bad input, message or conversation not found, or OpenAI unavailable.

**Note:** For hosted audio (e.g. `VOICE` with HTTPS in `content`, or the first **audio-like** row in `attachments` — `mimeType` `audio/*`, `kind` containing `recording` / `voice`, or common audio extensions), translate the **transcribed** text: call **transcribe** first (Whisper uses the first matching URL in a mixed bundle), then translate.

### `POST /api/v1/chat/conversations/:conversationId/messages/:messageId/transcribe`

**HTTP:** **200 OK** (not 201).

Transcribes or normalizes message text (OpenAI: Whisper for hosted audio when applicable, chat model for plain text). **Requires** `OPENAI_API_KEY` where used.

**Query (optional)**

| Param | Type | Description |
|--------|------|-------------|
| `force` | boolean | Same coercion rules as translate (`MessageAiQueryDto` in `chat.dto.ts`). |

**200** — serialized message with `transcribedMessage` populated or updated.

**400 / 404 / 503** — Same idea as translate (hosted voice URLs must fall under configured `AWS_BASE_URL` for URL-based transcription).

### `POST /api/v1/chat/users/:userId/push-tokens`

Registers or refreshes a push token for the given chat user.

**Body**

| Field | Type | Rules |
|--------|------|--------|
| `token` | string | Min length 10 |
| `platform` | enum | `IOS`, `ANDROID`, `WEB` |
| `deviceId` | string | Optional |

**201** — upserted `ChatUserPushToken` row (Nest default for `POST`; implemented as Prisma `upsert`).

---

## Socket.IO — Realtime chat

Connect to the same host/port as HTTP (path `/socket.io/`). Namespace defaults to `/`.

Canonical event strings live in `src/modules/chat/constants/chat-realtime.events.ts` (`ChatSocketClientEvent` for client → server, `ChatRealtimeEvent` for server → clients).

### Connection auth

1. **API key** — required. The Socket.IO middleware accepts the same colon header as HTTP (`X-Api-Key: <accessKey>:<secretKey>`), or `handshake.auth.apiKey` / `handshake.auth.xApiKey` (copied into the request as `X-Api-Key` for verification).

2. **Optional full chat session** — to join tenant presence and use `join_conversation` / `send_message` / receipts / typing / reactions, also send **both**:

- `token` — tenant JWT in **`handshake.auth.token` only** (the gateway does not read `Authorization` on the socket handshake)
- `userId` **or** `chatUserId` — chat profile id (`ChatUser.id`, numeric string)

JWT must be `typ: "tenant"`; `sub` must match the API key’s tenant. The server verifies the profile is **ACTIVE** in that tenant. If the JWT or profile id is missing, the socket may still **connect** (API key only), but chat events that require a profile will respond with errors such as `"Unauthorized"`.

### Rooms

- Tenant room: `tenant:<tenantId>` (joined on connect when JWT + user id are valid)
- Conversation room: `conversation:<conversationId>` — join via `join_conversation` event

### Client → server

| Event | Payload | Notes |
|--------|---------|--------|
| `join_conversation` | `{ conversationId }` | Asserts access, joins `conversation:<conversationId>` |
| `leave_conversation` | `{ conversationId }` | |
| `send_message` | `{ conversationId, type, content, replyToMessageId? }` | `type`: any Prisma `MessageType` the gateway allows (`TEXT`, `IMAGE`, `VOICE`, `VIDEO`, `FILE`, `LINK`, `OTHER`); non-empty `content`; optional **`replyToMessageId`** (numeric string) same rules as REST |
| `typing_start` | `{ conversationId }` | |
| `typing_stop` | `{ conversationId }` | |
| `react_message` | `{ conversationId, messageId, reactionType }` | |
| `remove_reaction` | `{ conversationId, messageId }` | |
| `message_delivered` | `{ conversationId, messageId }` | |
| `message_read` | `{ conversationId, messageId }` | |

### Server → clients

Payloads are emitted to conversation subscribers (and tenant-wide for presence).

| Event | When |
|--------|------|
| `message` | New message (same serialized shape as REST list/create: `attachments`, `replyTo*`, `reactions`, etc., when present) |
| `reaction_added` | `{ id, messageId, conversationId, userId, reactionType }` |
| `reaction_removed` | `{ messageId, conversationId, userId }` — after REST `DELETE .../reactions` or socket `remove_reaction` |
| `message_delivered` | `{ messageId, conversationId, userId, deliveredAt }` |
| `message_read` | `{ messageId, conversationId, userId, readAt }` |
| `user_typing` | `{ conversationId, userId, name }` |
| `user_stopped_typing` | `{ conversationId, userId }` |
| `user_online` | `{ userId, tenantId, name }` |
| `user_offline` | `{ userId, tenantId }` |

---

## Enums reference (JSON / Prisma)

| Name | Values |
|------|--------|
| `MessageType` | `TEXT`, `IMAGE`, `VOICE`, `VIDEO`, `FILE`, `LINK`, `OTHER` |
| `ParticipantRole` (conversation member) | `MEMBER`, `ADMIN` |
| `ChatUserStatus` | `ACTIVE`, `INACTIVE`, `SUSPENDED` |
| `DevicePlatform` | `IOS`, `ANDROID`, `WEB` |
| `ConversationType` | `DIRECT`, `GROUP`, `SUPPORT` |

### Related source (for implementers)

| Area | Path |
|------|------|
| Tenant feature flags & merge | `src/modules/tenants/tenant.constants.ts` |
| REST message DTOs & attachment validation | `src/modules/chat/dtos/chat.dto.ts` |
| Chat REST (messages, reactions, AI) | `src/modules/chat/controllers/chat.controller.ts` |
| Messages, replies, reactions, serialization | `src/modules/chat/services/chat.service.ts` |
| Socket wire events | `src/modules/chat/constants/chat-realtime.events.ts` |
| Attachment JSONB mapping | `src/modules/chat/utils/message-attachment-stored.util.ts` |
| Legacy `content` envelope (read paths) | `src/modules/chat/utils/message-media-envelope.util.ts` |
| Presigned S3 upload | `src/modules/upload/upload.controller.ts`, `src/modules/upload/upload.service.ts` |
| Prisma `Message` + `Tenant` | `prisma/schema.prisma` |
