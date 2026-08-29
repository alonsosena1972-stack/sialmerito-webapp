const crypto = require('crypto');

function getPath(obj, path) {
  return path.split('.').reduce((value, key) => value == null ? undefined : value[key], obj);
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });
  try {
    const event = req.body || {};
    const tx = event?.data?.transaction;
    const sig = event?.signature;
    const secret = process.env.WOMPI_EVENTS_SECRET;
    if (!secret || !event.event || !sig || !Array.isArray(sig.properties) || sig.timestamp == null) {
      return res.status(400).json({ error: 'Evento incompleto' });
    }
    const values = sig.properties.map((property) => getPath(event.data, property));
    if (values.some((value) => value === undefined || value === null)) {
      return res.status(400).json({ error: 'Propiedades de firma incompletas' });
    }
    const source = values.join('') + String(sig.timestamp) + secret;
    const checksum = crypto.createHash('sha256').update(source).digest('hex').toLowerCase();
    const received = String(req.headers['x-event-checksum'] || sig.checksum || '').toLowerCase();
    if (!received || received.length !== checksum.length || !crypto.timingSafeEqual(Buffer.from(received), Buffer.from(checksum))) {
      return res.status(401).json({ error: 'Firma de evento inválida' });
    }
    if (event.event === 'transaction.updated' && tx?.status === 'APPROVED') {
      console.log(JSON.stringify({ type: 'wompi_payment_approved', id: tx.id, reference: tx.reference, email: tx.customer_email, amount_in_cents: tx.amount_in_cents }));
      // El envío del informe se conecta en el siguiente paso, después de asociar
      // la referencia de pago con el intento y el archivo de retroalimentación.
    }
    return res.status(200).json({ received: true });
  } catch (_) {
    return res.status(400).json({ error: 'Evento no válido' });
  }
};
