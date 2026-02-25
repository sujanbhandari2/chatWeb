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
