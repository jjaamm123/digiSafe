# Digital Safety AI Platform - Backend API

This is the Express.js backend for Phase 1 of the capstone project.

## Installation & Setup

1. From the `backend` folder, install the required dependencies:
   ```bash
   npm install
   ```

2. Start the development server (runs with automatic file reload):
   ```bash
   npm run dev
   ```
   Or start standard production execution:
   ```bash
   npm start
   ```

## Endpoint Specification

### `POST /api/scan`

Scans text content for safety threats (phishing, scam, misinformation).

**Request Headers:**
- `Content-Type: application/json`

**Request Body:**
```json
{
  "text": "Please update your password by clicking here",
  "source": "gmail"
}
```

**Response Body (JSON):**
```json
{
  "success": true,
  "data": {
    "analyzedAt": "2026-06-20T10:28:00.000Z",
    "source": "gmail",
    "riskLevel": "HIGH",
    "riskScore": 88,
    "classification": "Phishing Attempt",
    "indicators": [
      "Requests credential modifications",
      "Urgent call-to-action phrasing detected"
    ],
    "flaggedPhrases": [
      "password"
    ]
  }
}
```
