

// server.js
require('dotenv').config();
const express = require('express');
const Stripe = require('stripe');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();

// CORS: permite apenas o frontend configurado no .env (ajusta se precisares)
const FRONTEND = (process.env.FRONTEND_URL || 'http://127.0.0.1:5500').replace(/\/$/, '');
app.use(cors({ origin: FRONTEND }));
app.use(bodyParser.json());

// Segurança: valida que existe a chave no .env
if (!process.env.STRIPE_SECRET_KEY) {
  console.error('Missing STRIPE_SECRET_KEY in .env. Aborting.');
  process.exit(1);
}
if (!process.env.PRICE_ID_MONTHLY || !process.env.PRICE_ID_YEARLY) {
  console.warn(
    'PRICE_ID_MONTHLY or PRICE_ID_YEARLY missing in .env. Ensure both are set for monthly and yearly prices.'
  );
}

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// CREATE CHECKOUT SESSION
app.post('/create-checkout-session', async (req, res) => {
  try {
    const { billing = 'monthly', customerEmail, priceId: priceIdFromClient } = req.body;

    // If client sent a priceId, prefer it (frontend can send priceId directly).
    const priceId =
      priceIdFromClient || (billing === 'yearly' ? process.env.PRICE_ID_YEARLY : process.env.PRICE_ID_MONTHLY);

    if (!priceId) {
      return res.status(400).json({
        error:
          'Missing price id on server. Set PRICE_ID_MONTHLY / PRICE_ID_YEARLY in .env or send priceId from the client.',
      });
    }

    // success + cancel urls (Stripe substitui {CHECKOUT_SESSION_ID})
    const successUrl = `${FRONTEND}/frontend/checkout-success.html?session_id={CHECKOUT_SESSION_ID}`;
    const cancelUrl = `${FRONTEND}/frontend/checkout-cancel.html?billing=${encodeURIComponent(billing)}`;

    console.log(`Creating Stripe Checkout session (billing=${billing}, email=${customerEmail || 'none'})`);
    console.log('DEBUG: chosen priceId =', priceId);

    // optional: verifica no Stripe qual o intervalo do price (month/year)
    try {
      const priceObj = await stripe.prices.retrieve(priceId);
      console.log(
        'DEBUG: price.recurring.interval =',
        priceObj.recurring?.interval,
        ' unit_amount =',
        priceObj.unit_amount,
        'currency=',
        priceObj.currency
      );

      // Safety check: if the client requested billing but the env price doesn't match, reject
      if (!priceIdFromClient && billing) {
        const expectedInterval = billing === 'yearly' ? 'year' : 'month';
        if (priceObj.recurring?.interval !== expectedInterval) {
          console.error(
            'ENV price ID mismatch: expected',
            expectedInterval,
            'but env price has interval',
            priceObj.recurring?.interval
          );
          return res.status(500).json({
            error: 'Server configuration error: price id not matching requested billing period',
          });
        }
      }
    } catch (e) {
      console.warn('DEBUG: could not retrieve price object', e.message);
      // continue — Stripe will error later if priceId is invalid
    }

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      ...(customerEmail ? { customer_email: customerEmail } : {}),
      success_url: successUrl,
      cancel_url: cancelUrl,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Create session error:', err);
    res.status(500).json({ error: err.message || 'Internal server error creating checkout session' });
  }
});

// SESSION DETAILS (o frontend success page chama isto)
app.get('/session', async (req, res) => {
  try {
    const sessionId = req.query.session_id;
    if (!sessionId) return res.status(400).json({ error: 'session_id query param required' });

    const session = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ['line_items.data.price.product', 'subscription', 'latest_invoice'],
    });

    const result = {
      id: session.id,
      customer_email: session.customer_email || session.customer_details?.email || null,
      price_name:
        session.line_items?.data?.[0]?.price?.product?.name ||
        session.line_items?.data?.[0]?.description ||
        null,
      line_items: session.line_items || null,
      subscription: session.subscription ? { id: session.subscription.id, status: session.subscription.status } : null,
      subscription_status: session.subscription?.status || null,
      latest_invoice: session.latest_invoice || null,
    };

    res.json(result);
  } catch (err) {
    console.error('Error fetching session:', err);
    res.status(500).json({ error: err.message || 'Internal server error fetching session' });
  }
});

// healthcheck
app.get('/', (req, res) => res.send('OK - server running'));

// start server
const PORT = process.env.PORT || 4242;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}  (FRONTEND_URL=${FRONTEND})`));
