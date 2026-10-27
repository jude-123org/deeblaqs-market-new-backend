# DeeBlaq's Market — New Backend

Independent Express API for the new DeeBlaq's Market project.

## Render settings

- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`

## Environment variables

Set these in Render's Environment page, not in GitHub:

- `SUPABASE_URL` — the URL for the new Supabase project
- `SUPABASE_SERVICE_ROLE_KEY` — the new project's service-role/secret key
- `FRONTEND_URL` — the exact deployed frontend origin, e.g. `https://your-site.example`; multiple origins may be comma-separated
- `NODE_ENV` — `production`

Never put the service-role key in browser HTML, public GitHub files, screenshots, or chat.

## Initial endpoints

- `GET /` and `GET /health`
- `GET /api/categories`
- `GET /api/products`
- `POST /api/auth/signup`
- `POST /api/auth/login`
- `GET /api/me` (requires `Authorization: Bearer <access_token>`)

## Important before production

This is a starter, not a complete live-commerce backend. The existing schema has no confirmed stock/inventory model or payment-verification fields. Do not enable real payments or wallet credits until payment webhooks, atomic balance changes, inventory delivery, and order creation are implemented and tested. The signup route creates an unconfirmed account; configure Supabase email confirmation and SMTP before relying on it in production.
