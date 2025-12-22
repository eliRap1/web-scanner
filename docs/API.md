# Web Scanner – Auth API Documentation

> This document covers the **Authentication** service (Registration + Login/Token).

## Base URLs (development)

- Registration service: `http://localhost:8001`
- Login service: `http://localhost:8002`

## Authentication scheme

After login you receive a **session token**.

Send it on protected requests using the HTTP header:

```
Authorization: Bearer <token>
```

Some endpoints also accept the token in the **request body** as a fallback (useful for tools that can’t set headers).

---

## 1) Register

**POST** `/register`

### Request body
```json
{
  "username": "testuser",
  "email": "test@example.com",
  "password": "Test@1234",
  "confirm_password": "Test@1234"
}
```

### Success response (201)
```json
{
  "status": "ok",
  "user_id": 1,
  "message": "user created successfully"
}
```

### Validation errors (422)
Example: password does not meet policy.
```json
{
  "detail": [
    {
      "type": "value_error",
      "loc": ["body", "password"],
      "msg": "Value error, password must contain at least one special character",
      "input": "Password123"
    }
  ]
}
```

### Business errors (400)
- Username already taken
- Email already registered

Example:
```json
{
  "detail": "username already taken"
}
```

### Curl
```bash
curl -X POST http://localhost:8001/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"Test@1234","confirm_password":"Test@1234"}'
```

---

## 2) Login

**POST** `/login`

### Request body
```json
{
  "username": "testuser",
  "password": "Test@1234"
}
```

### Success response (200)
```json
{
  "status": "ok",
  "token": "<SESSION_TOKEN>",
  "user_id": 1,
  "username": "testuser",
  "role": "user",
  "message": "login successful"
}
```

### Error response (401)
```json
{
  "detail": "Invalid username or password"
}
```

### Curl
```bash
curl -X POST http://localhost:8002/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"Test@1234"}'
```

---

## 3) Verify token

**GET** `/verify`

Token can be provided:
- Preferred: `Authorization: Bearer <token>`
- Backward-compat: query param `?token=<token>`

### Success response (200)
```json
{
  "status": "ok",
  "valid": true,
  "user_id": 1,
  "username": "testuser",
  "role": "user"
}
```

### Error response (401)
```json
{
  "detail": "Invalid or expired token"
}
```

### Curl (header)
```bash
curl -X GET http://localhost:8002/verify \
  -H "Authorization: Bearer <SESSION_TOKEN>"
```

---

## 4) Logout

**POST** `/logout`

Token can be provided:
- Preferred: `Authorization: Bearer <token>`
- Fallback body: `{ "token": "<token>" }`

### Success response (200)
```json
{
  "status": "ok",
  "message": "logged out successfully"
}
```

### Error response (400)
```json
{
  "detail": "Missing token (send in Authorization header or body)"
}
```

### Curl
```bash
curl -X POST http://localhost:8002/logout \
  -H "Authorization: Bearer <SESSION_TOKEN>"
```

---

## 5) Refresh token

**POST** `/refresh`

This endpoint rotates the token:
- If token is valid: returns a **new token** and invalidates the old one.
- If token is invalid/expired: returns 401.

Token can be provided:
- Preferred: `Authorization: Bearer <token>`
- Fallback body: `{ "token": "<token>" }`

### Success response (200)
```json
{
  "status": "ok",
  "token": "<NEW_SESSION_TOKEN>",
  "user_id": 1,
  "username": "testuser",
  "role": "user",
  "message": "token refreshed"
}
```

### Error response (401)
```json
{
  "detail": "Invalid or expired token"
}
```

### Curl
```bash
curl -X POST http://localhost:8002/refresh \
  -H "Authorization: Bearer <SESSION_TOKEN>"
```

---

## 6) Health

**GET** `/health`

### Response (200)
```json
{
  "status": "ok",
  "service": "registration"
}
```

(or `"service": "login"` for the login service)
