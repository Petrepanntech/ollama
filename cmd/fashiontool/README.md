# Fashion Tool (Bespoke Female Wears)

A minimal backend for bespoke fashion operations with:

- SQLite database
- Email/password authentication
- Customer management
- Measurements tracking
- Order management

## Run

```bash
go run ./cmd/fashiontool
```

Environment variables:

- `FASHION_TOOL_ADDR` (default `:8088`)
- `FASHION_TOOL_DB` (default `fashion_tool.db`)

## API

- `POST /auth/register` `{ "email": "...", "password": "..." }`
- `POST /auth/login` `{ "email": "...", "password": "..." }`
- `GET /auth/me` (Bearer token)
- `POST /customers` (Bearer token)
- `GET /customers` (Bearer token)
- `POST /customers/{id}/measurements` (Bearer token)
- `GET /customers/{id}/measurements` (Bearer token)
- `POST /orders` (Bearer token)
- `GET /orders` (Bearer token)
