# Authentication API Documentation

## Overview
Clean authentication system with email verification using Gmail SMTP.

## Endpoints

### 1. Register User
**POST** `/auth/register`

Create a new user account and send verification email.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

**Response (201):**
```json
{
  "message": "Account created successfully! Please check your email to verify your account.",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "email_confirmed_at": null,
    "created_at": "2024-01-01T00:00:00"
  },
  "requires_verification": true,
  "note": "You must verify your email before signing in"
}
```

**Errors:**
- `400` - Invalid email format or weak password
- `409` - Email already exists
- `500` - Server error

---

### 2. Verify Email
**GET** `/auth/verify-email/<token>`

Verify email using token from verification email link.

**Response (200):**
```json
{
  "message": "Email verified successfully! You can now sign in.",
  "email": "user@example.com"
}
```

**Errors:**
- `400` - Invalid or expired token
- `404` - User not found
- `500` - Server error

---

### 3. Sign In
**POST** `/auth/signin`

Sign in with verified email and password.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

**Response (200):**
```json
{
  "message": "Sign in successful",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "email_confirmed_at": "2024-01-01T00:00:00",
    "created_at": "2024-01-01T00:00:00"
  },
  "session": {
    "access_token": "eyJ...",
    "refresh_token": "...",
    "expires_at": 1234567890,
    "expires_in": 3600,
    "token_type": "bearer"
  }
}
```

**Errors:**
- `401` - Invalid email or password
- `403` - Email not verified
- `500` - Server error

---

### 4. Resend Verification Email
**POST** `/auth/resend-verification`

Resend verification email for unverified accounts.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "message": "Verification email sent. Please check your inbox."
}
```

**Errors:**
- `400` - Invalid email or already verified
- `404` - User not found
- `500` - Server error

---

### 5. Get Current User
**GET** `/auth/me`

Get authenticated user information.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "email_confirmed_at": "2024-01-01T00:00:00",
    "created_at": "2024-01-01T00:00:00"
  }
}
```

**Errors:**
- `401` - Missing or invalid token
- `500` - Server error

---

### 6. Create or Update Tenant Profile
**POST** `/api/tenants/profile`

Create/update tenant onboarding details for the authenticated user.
Supported `tenant_type` values: `self_managed`, `white_label`.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
  "tenant_name": "Acme Gov Department",
  "tenant_type": "self_managed",
  "tenant_details": {
    "country": "Netherlands",
    "contact_email": "admin@acme.gov"
  }
}
```

**Response (200):**
```json
{
  "message": "Tenant profile saved successfully",
  "tenant": {
    "id": "uuid",
    "tenant_name": "Acme Gov Department",
    "tenant_type": "self_managed",
    "tenant_details": {
      "country": "Netherlands",
      "contact_email": "admin@acme.gov"
    },
    "pinecone_index_name": "tenant-uuid"
  }
}
```

**Errors:**
- `400` - Validation error
- `401` - Missing/invalid token
- `500` - Server error

---

### 7. Get Tenant Profile
**GET** `/api/tenants/profile`

Get tenant details for the authenticated user.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
  "tenant": {
    "id": "uuid",
    "tenant_name": "Acme Gov Department",
    "tenant_type": "self_managed",
    "tenant_details": {},
    "pinecone_index_name": "tenant-uuid"
  }
}
```

**Errors:**
- `401` - Missing/invalid token
- `404` - Tenant profile not found
- `500` - Server error

---

## Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number

## Token Expiration
- Access tokens: 1 hour
- Verification tokens: 24 hours

