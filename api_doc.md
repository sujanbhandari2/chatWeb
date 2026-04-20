# Vitafy Chat Backend — API Reference

Base URL defaults to `http://localhost:4040` (see `PORT` and `HOST` in `.env`). All JSON bodies use `Content-Type: application/json` unless noted.

**Global HTTP prefix:** `api`  
**URI versioning:** `v1` (Nest default version)  

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

### Tenant scope (chat)

Chat routes are scoped by the **API key’s tenant** (`request.userId` from the key row). There is no separate company header.

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

**200** — `data`:

```json
{
  "token": "<jwt>",
  "id": "<tenant id>",
  "email": "<string>",
  "name": "<string>",
  "settings": {}
}
```

**401** — Unknown email or bad password (`Invalid credentials`).

---

## Admin — `/api/v1/admin`

### `POST /api/v1/admin/login`

**Body:** `email`, `password` (same rules as tenant login).

**200** — `data`:

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

**Create/update 200** — public tenant shape: `id`, `email`, `name`, `settings`, `createdAt`.

**List 200** — `data`: array of public tenant shapes (same fields as create/update).

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

---

## Shared (tenant JWT) — `/api/v1/shared`

### `GET /api/v1/shared/me`

Tenant Bearer JWT + tenant-only guard.

**200** — `data`: `{ id, email, name, settings, createdAt }`.

### API keys (own keys) — `/api/v1/shared/api-keys`

Tenant Bearer JWT required.

| Method | Path |
|--------|------|
| `GET` | `/api/v1/shared/api-keys` |
| `POST` | `/api/v1/shared/api-keys` |
| `POST` | `/api/v1/shared/api-keys/:id/revoke` |

Same DTOs and semantics as admin key routes; `:id` is the API key row id.

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

Messages are ordered **newest first** (`createdAt` desc). Soft-deleted messages are omitted. Each item is a serialized message:

| Field | Notes |
|--------|--------|
| `id`, `conversationId`, `tenantId`, `senderId`, `type`, `content`, `createdAt`, `deletedAt` | As stored |
| `sender` | `{ id, name }` when loaded |

There is **no** automatic signed `url` field in the current serializer; `content` is stored text/object reference as persisted.

### `POST /api/v1/chat/conversations/:conversationId/messages`

REST send (also broadcasts over Socket.IO to the conversation room).

**Body**

| Field | Type | Rules |
|--------|------|--------|
| `senderId` | numeric string | Chat user id sending the message (must be participant, same tenant) |
| `type` | enum | `TEXT`, `IMAGE`, `VOICE`, `VIDEO`, `FILE`, `LINK`, `OTHER` (Prisma `MessageType`) |
| `content` | string | 1–50000 chars |

**201** — created message (Prisma include `sender`).

### `POST /api/v1/chat/users/:userId/push-tokens`

Registers or refreshes a push token for the given chat user.

**Body**

| Field | Type | Rules |
|--------|------|--------|
| `token` | string | Min length 10 |
| `platform` | enum | `IOS`, `ANDROID`, `WEB` |
| `deviceId` | string | Optional |

**200/201** — upserted `ChatUserPushToken` row.

---

## Socket.IO — Realtime chat

Connect to the same host/port as HTTP (path `/socket.io/`). Namespace defaults to `/`.

Canonical event strings live in `src/modules/chat/constants/chat-realtime.events.ts` (`ChatSocketClientEvent` for client → server, `ChatRealtimeEvent` for server → clients).

### Connection auth

1. **API key** — required. The Socket.IO middleware accepts the same colon header as HTTP (`X-Api-Key: <accessKey>:<secretKey>`), or `handshake.auth.apiKey` / `handshake.auth.xApiKey` (copied into the request as `X-Api-Key` for verification).

2. **Optional full chat session** — to join tenant presence and use `join_conversation` / `send_message` / receipts / typing / reactions, also send **both**:

- `token` — tenant JWT in **`handshake.auth.token` only** (the gateway does **not** read `Authorization: Bearer …` on the WebSocket handshake)
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
| `send_message` | `{ conversationId, type, content }` | `type`: any Prisma `MessageType` the gateway allows (`TEXT`, `IMAGE`, `VOICE`, `VIDEO`, `FILE`, `LINK`, `OTHER`); non-empty `content` |
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
| `message` | New message (serialized like REST `serializeMessage`) |
| `reaction_added` | `{ id, messageId, conversationId, userId, reactionType }` |
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

---

#API JSONS

## ADMIN API JSON

{"openapi":"3.0.0","paths":{"/api/v1/admin/login":{"post":{"operationId":"AdminAuthController_login_v1","parameters":[],"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/AdminLoginDto"}}}},"responses":{"201":{"description":""}},"summary":"Admin login (JWT for admin routes)","tags":["Admin Auth"]}},"/api/v1/admin/me":{"get":{"operationId":"AdminAuthController_me_v1","parameters":[],"responses":{"200":{"description":""}},"security":[{"bearer":[]}],"summary":"Current admin profile","tags":["Admin Auth"]}},"/api/v1/admin/tenants":{"get":{"operationId":"TenantsAdminController_list_v1","parameters":[],"responses":{"200":{"description":""}},"security":[{"bearer":[]}],"summary":"List all tenants","tags":["Tenants (Admin)"]},"post":{"operationId":"TenantsAdminController_create_v1","parameters":[],"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/CreateTenantDto"}}}},"responses":{"201":{"description":""}},"security":[{"bearer":[]}],"tags":["Tenants (Admin)"]}},"/api/v1/admin/tenants/{id}":{"patch":{"operationId":"TenantsAdminController_update_v1","parameters":[{"name":"id","required":true,"in":"path","schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/UpdateTenantDto"}}}},"responses":{"200":{"description":""}},"security":[{"bearer":[]}],"tags":["Tenants (Admin)"]},"delete":{"operationId":"TenantsAdminController_remove_v1","parameters":[{"name":"id","required":true,"in":"path","schema":{"type":"string"}}],"responses":{"200":{"description":""}},"security":[{"bearer":[]}],"tags":["Tenants (Admin)"]}},"/api/v1/admin/tenants/{userId}/api-keys":{"get":{"operationId":"ApiKeysAdminController_list_v1","parameters":[{"name":"userId","required":true,"in":"path","description":"Tenant id","schema":{"type":"string"}}],"responses":{"200":{"description":""}},"security":[{"bearer":[]}],"summary":"List API keys for a tenant","tags":["Admin API Keys"]},"post":{"operationId":"ApiKeysAdminController_create_v1","parameters":[{"name":"userId","required":true,"in":"path","description":"Tenant id","schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/CreateApiKeyDto"}}}},"responses":{"201":{"description":""}},"security":[{"bearer":[]}],"summary":"Create API key for a tenant","tags":["Admin API Keys"]}},"/api/v1/admin/tenants/{userId}/api-keys/{id}/revoke":{"post":{"operationId":"ApiKeysAdminController_revoke_v1","parameters":[{"name":"userId","required":true,"in":"path","description":"Tenant id","schema":{"type":"string"}},{"name":"id","required":true,"in":"path","description":"API key id","schema":{"type":"string"}}],"responses":{"201":{"description":""}},"security":[{"bearer":[]}],"summary":"Revoke an API key for a tenant","tags":["Admin API Keys"]}}},"info":{"title":"Admin API","description":"Admin JWT routes: profile and tenant management.","version":"1.0","contact":{}},"tags":[],"servers":[],"components":{"securitySchemes":{"bearer":{"scheme":"bearer","bearerFormat":"JWT","type":"http"}},"schemas":{"AdminLoginDto":{"type":"object","properties":{"email":{"type":"string","example":"admin@example.com"},"password":{"type":"string","minLength":8}},"required":["email","password"]},"CreateTenantDto":{"type":"object","properties":{"name":{"type":"string","maxLength":200},"email":{"type":"string"},"password":{"type":"string","minLength":8}},"required":["name","email","password"]},"UpdateTenantDto":{"type":"object","properties":{"name":{"type":"string","maxLength":200},"email":{"type":"string"},"password":{"type":"string","minLength":8}}},"CreateApiKeyDto":{"type":"object","properties":{"name":{"type":"string","maxLength":120},"scopes":{"type":"array","items":{"type":"string"}},"expiresAt":{"type":"string"}}}}}}



## TENANT API JSON

{"openapi":"3.0.0","paths":{"/api/v1/auth/tenant/login":{"post":{"operationId":"AuthController_tenantLogin_v1","parameters":[],"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/TenantLoginDto"}}}},"responses":{"201":{"description":""}},"tags":["Auth"]}},"/api/v1/system/health":{"get":{"operationId":"AppController_health_v1","parameters":[],"responses":{"200":{"description":""}},"tags":[""]}},"/api/v1/shared/me":{"get":{"operationId":"TenantsSelfController_me_v1","parameters":[],"responses":{"200":{"description":""}},"security":[{"bearer":[]}],"tags":["shared"]}},"/api/v1/shared/api-keys":{"get":{"operationId":"ApiKeyController_list_v1","parameters":[],"responses":{"200":{"description":""}},"security":[{"bearer":[]}],"tags":["shared"]},"post":{"operationId":"ApiKeyController_create_v1","parameters":[],"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/CreateApiKeyDto"}}}},"responses":{"201":{"description":""}},"security":[{"bearer":[]}],"tags":["shared"]}},"/api/v1/shared/api-keys/{id}/revoke":{"post":{"operationId":"ApiKeyController_revoke_v1","parameters":[{"name":"id","required":true,"in":"path","schema":{"type":"string"}}],"responses":{"201":{"description":""}},"security":[{"bearer":[]}],"tags":["shared"]}}},"info":{"title":"Tenant API","description":"Routes for tenant applications: auth, system, and shared resources (profile, API keys).\n\nChat REST lives under `/api/v1/chat/...` (see the Chat OpenAPI document); it uses `X-Api-Key: accessKey:secretKey`.","version":"1.0","contact":{}},"tags":[],"servers":[],"components":{"securitySchemes":{"bearer":{"scheme":"bearer","bearerFormat":"JWT","type":"http"},"apiKey":{"type":"apiKey","in":"header","name":"X-Api-Key"}},"schemas":{"TenantLoginDto":{"type":"object","properties":{"email":{"type":"string","example":"tenant@example.com"},"password":{"type":"string","minLength":8}},"required":["email","password"]},"CreateApiKeyDto":{"type":"object","properties":{"name":{"type":"string","maxLength":120},"scopes":{"type":"array","items":{"type":"string"}},"expiresAt":{"type":"string"}}}}}}



## CHAT API JSON

{"openapi":"3.0.0","paths":{"/api/v1/chat/tenant":{"get":{"operationId":"ChatUsersController_getTenant_v1","parameters":[],"responses":{"200":{"description":""}},"security":[{"apiKey":[]}],"tags":["chat"]}},"/api/v1/chat/users":{"post":{"operationId":"ChatUsersController_createUser_v1","parameters":[],"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/CreateUserDto"}}}},"responses":{"201":{"description":""}},"security":[{"apiKey":[]}],"tags":["chat"]},"get":{"operationId":"ChatUsersController_listUsers_v1","parameters":[],"responses":{"200":{"description":""}},"security":[{"apiKey":[]}],"tags":["chat"]}},"/api/v1/chat/conversations":{"post":{"operationId":"ChatController_createConversation_v1","parameters":[],"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/CreateConversationDto"}}}},"responses":{"201":{"description":""}},"security":[{"apiKey":[]}],"tags":["chat"]},"get":{"operationId":"ChatController_listConversations_v1","parameters":[{"name":"forUserId","required":false,"in":"query","schema":{"type":"string"}}],"responses":{"200":{"description":""}},"security":[{"apiKey":[]}],"tags":["chat"]}},"/api/v1/chat/conversations/{conversationId}/participants":{"post":{"operationId":"ChatController_addParticipant_v1","parameters":[{"name":"conversationId","required":true,"in":"path","schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/AddParticipantDto"}}}},"responses":{"201":{"description":""}},"security":[{"apiKey":[]}],"tags":["chat"]}},"/api/v1/chat/conversations/{conversationId}/messages":{"get":{"operationId":"ChatController_listMessages_v1","parameters":[{"name":"conversationId","required":true,"in":"path","schema":{"type":"string"}},{"name":"page","required":false,"in":"query","schema":{"minimum":1,"default":1,"type":"number"}},{"name":"pageSize","required":false,"in":"query","schema":{"minimum":1,"maximum":100,"default":20,"type":"number"}}],"responses":{"200":{"description":""}},"security":[{"apiKey":[]}],"tags":["chat"]},"post":{"operationId":"ChatController_postMessage_v1","parameters":[{"name":"conversationId","required":true,"in":"path","schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/CreateRestMessageDto"}}}},"responses":{"201":{"description":""}},"security":[{"apiKey":[]}],"tags":["chat"]}},"/api/v1/chat/users/{userId}/push-tokens":{"post":{"operationId":"ChatController_registerPush_v1","parameters":[{"name":"userId","required":true,"in":"path","schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/RegisterPushTokenDto"}}}},"responses":{"201":{"description":""}},"security":[{"apiKey":[]}],"tags":["chat"]}}},"info":{"title":"Chat API","description":"Conversations and messaging under `/api/v1/chat/...`. Authenticate with `X-Api-Key: accessKey:secretKey` (`ApiKeyGuard`).","version":"1.0","contact":{}},"tags":[],"servers":[],"components":{"securitySchemes":{"apiKey":{"type":"apiKey","in":"header","name":"X-Api-Key"}},"schemas":{"CreateUserDto":{"type":"object","properties":{"providerId":{"type":"string","description":"Identity provider or source system key for this user (stored as `provider_id`)."},"providerUserId":{"type":"string","description":"User id from that provider / your system (stored as `provider_user_id`)."},"email":{"type":"string"},"name":{"type":"string","description":"Display name; defaults to email local-part if omitted."}},"required":["providerId","providerUserId","email"]},"CreateConversationDto":{"type":"object","properties":{"type":{"type":"string","enum":["DIRECT","GROUP","SUPPORT"]},"creatorUserId":{"type":"string","description":"Required when type is GROUP. This chat user is added as a participant with ADMIN role."},"participantIds":{"description":"GROUP: extra members besides `creatorUserId`. DIRECT / SUPPORT: optional initial participants (all MEMBER); omit for an empty thread and add via `POST .../participants`.","type":"array","items":{"type":"string"}}}},"AddParticipantDto":{"type":"object","properties":{"userId":{"type":"string","description":"Chat user profile id (numeric string)."},"actorUserId":{"type":"string","description":"Chat user performing this add. Required for group conversations; must be a participant with ADMIN role."}},"required":["userId"]},"CreateRestMessageDto":{"type":"object","properties":{"type":{"type":"string","enum":["TEXT","IMAGE","VOICE","VIDEO","FILE","LINK","OTHER"]},"content":{"type":"string"},"senderId":{"type":"string","description":"Chat user profile id (numeric string)."}},"required":["type","content","senderId"]},"RegisterPushTokenDto":{"type":"object","properties":{"token":{"type":"string"},"platform":{"type":"string","enum":["IOS","ANDROID","WEB"]},"deviceId":{"type":"string"}},"required":["token","platform"]}}}}