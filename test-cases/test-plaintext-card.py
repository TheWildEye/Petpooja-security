# Plaintext Card Data Test Case — PCI DSS Req 3 Violation
# This file contains an INTENTIONAL compliance violation for testing.

import sqlite3

def store_payment(user_id, card_number, cvv, expiry, amount):
    """VIOLATION: Storing card data in plaintext — PCI DSS Req 3"""
    conn = sqlite3.connect("payments.db")
    cursor = conn.cursor()
    
    # VULNERABILITY: Card number stored in plaintext
    cursor.execute("""
        INSERT INTO payments (user_id, card_number, cvv, expiry_date, amount)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, card_number, cvv, expiry, amount))
    
    conn.commit()
    conn.close()

def get_payment_history(user_id):
    """VIOLATION: Returns raw card numbers in API response"""
    conn = sqlite3.connect("payments.db")
    cursor = conn.cursor()
    cursor.execute("SELECT card_number, amount, expiry_date FROM payments WHERE user_id=?", (user_id,))
    results = cursor.fetchall()
    # VULNERABILITY: Full card numbers returned to client
    return [{"card": r[0], "amount": r[1], "expiry": r[2]} for r in results]

def log_transaction(card_number, amount, status):
    """VIOLATION: Card number in logs"""
    # VULNERABILITY: PCI DSS Req 3 — never log full card numbers
    print(f"Transaction: card={card_number}, amount={amount}, status={status}")
    
    import logging
    logger = logging.getLogger('payments')
    logger.info(f"Payment processed: {card_number} for ${amount}")

# VIOLATION: Hardcoded Razorpay key
RAZORPAY_KEY_ID = "rzp_live_1234567890abcd"
RAZORPAY_KEY_SECRET = "AbCdEfGhIjKlMnOpQrStUvWx"

# SAFE EXAMPLE:
# Use tokenization — never store raw card numbers
# stripe.tokens.create({card: {number, exp_month, exp_year, cvc}})
# Store only last 4 digits for display: card[-4:]
