# Frontend Test Client

Minimal React client for manual verification:
- Register/Login with unique `username` + `password`
- See currently online users (`isOnline`)
- Auto-open global conversation for all registered users
- Send text messages to all users in global chat
- Start direct chats (AGENT/ADMIN)
- Upload/send image messages
- Record/upload/send voice messages (mock accepted)
- React to messages
- Mark messages as read
- Soft-delete messages

## Run
```bash
npm install
cp .env.example .env
npm run dev
```

## Embeddable widget

- **Configurator (embed settings UI):** [config.html](config.html) → e.g. `http://localhost:5173/config.html` — edit options, copy iframe URL, live preview.
- **Widget runtime:** [widget.html](widget.html) → e.g. `http://localhost:5173/widget.html?tenantId=…`.
- Build outputs `dist/widget.html`, `dist/config.html`, and shared assets. See [docs/WIDGET_EMBED.md](docs/WIDGET_EMBED.md) for iframe, loader, and security notes.
