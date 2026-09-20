# Phase 28 — Manual notification delivery

Notifications are explicitly human-triggered. An organization administrator or incident commander submits a title and message to `POST /api/v1/notifications/deliver`; the API then sends it to one configured server-side HTTPS webhook.

Set these API environment variables when a destination has been approved:

```env
NOTIFICATION_WEBHOOK_URL=https://approved-destination.example/webhook
NOTIFICATION_WEBHOOK_PROVIDER=generic # generic, slack, or teams
```

The browser never receives the destination URL or credentials. There is no scheduler, automatic alerting, or autonomous delivery in this phase.

