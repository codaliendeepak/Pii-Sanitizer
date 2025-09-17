# 📦 pii-sanitizer

`pii-sanitizer` is a lightweight Node.js library for sanitizing **Personally Identifiable Information (PII)** such as phone numbers, Aadhaar numbers, emails, and passwords from request bodies. It also provides encoding/decoding utilities for safely handling sensitive data.

---

## 🚀 Features

* 🔒 Encode and decode PII using a signing secret.
* 🔍 Sanitize fields based on:

  * **Explicit field names** (`fieldsToSanitize`)
  * **Regex patterns** (`regexToSanitize`)
  * **Default mode** → sanitize all if no configuration is provided.
* 🛑 Skip specific fields (`fieldsToSkip`).
* ✅ Allowlist specific routes (`allowListRoutes`).
* ⚡ Works with both **Express** and **Fastify**.

---

## 📦 Installation

```bash
npm install pii-sanitizer
```

Or using Yarn:

```bash
yarn add pii-sanitizer
```

---

## 🛠️ Usage

### Basic Example

```ts Express
import express from "express";
import bodyParser from "body-parser";
import { Sanitizer } from "pii-sanitizer";

const app = express();
app.use(bodyParser.json());

// Initialize sanitizer
const sanitizer = new Sanitizer({
  signingSecret: "thisissecretkeyforme",
  fieldsToSanitize: ["password", "email"],
  regexToSanitize: [/\d{10}/], // sanitize phone numbers with 10 digits
});

// Middleware usage
app.use((req, res, next) => {
  req.body = sanitizer.encodeBody(req.body);
  next();
});

// Test route
app.post("/register", (req, res) => {
  res.json({ sanitizedBody: req.body });
});

app.listen(3000, () => console.log("Server running on port 3000"));
```

```ts Fastify
import Fastify from "fastify";
import { Sanitizer } from "pii-sanitizer";

const fastify = Fastify();

const sanitizer = new Sanitizer({
  signingSecret: "thisissecretkeyforme",
  allowlistRoutes: [/\/signup/],  // only sanitize these routes
});

fastify.addHook("preHandler", async (req, reply) => {
  req.body = sanitizer.sanitizeObject(req.body, req.url);
});

fastify.post("/signup", async (req, reply) => {
  return { body: req.body };
});

fastify.listen({ port: 3000 });

### Decoding Example

```ts
const decodedBody = sanitizer.decodeBody(req.body);
console.log(decodedBody);
```

---

## ⚙️ Configuration Options

| Option             | Type       | Description                                                          |
| ------------------ | ---------- | -------------------------------------------------------------------- |
| `signingSecret`    | `string`   | Secret key used for encoding/decoding.                               |
| `fieldsToSanitize` | `string[]` | Specific field names to sanitize (e.g., `password`, `email`).        |
| `regexToSanitize`  | `RegExp[]` | Regex patterns to match values (e.g., `/\d{10}/` for phone numbers). |
| `fieldsToSkip`     | `string[]` | Fields to exclude from sanitization.                                 |
| `allowListRoutes`  | `string[]` | Routes where sanitization is skipped.                                |

---

## 📄 Example Request

### Input:

```json
{
  "username": "JohnDoe",
  "password": "mysecretpass",
  "email": "john@example.com",
  "phone": "9876543210"
}
```

### Output (Sanitized):

```json
{
  "username": "JohnDoe",
  "password": "ENC:1a2b3c...",
  "email": "ENC:7f8e9d...",
  "phone": "ENC:a9b8c7..."
}
```

### Decoded:

```json
{
  "username": "JohnDoe",
  "password": "mysecretpass",
  "email": "john@example.com",
  "phone": "9876543210"
}
```

---

## 🧪 Scripts

* **Start example server**

  ```bash
  npm start
  ```

* **Build package**

  ```bash
  npm run build
  ```

---

## 📜 License

MIT © 2025 Deepak Gera
