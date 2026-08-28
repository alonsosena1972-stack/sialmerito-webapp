const crypto = require('crypto');

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }
  try {
    const { reference, amountInCents, currency = 'COP' } = req.body || {};
    if (!reference || !Number.isInteger(amountInCents) || amountInCents <= 0) {
      return res.status(400).json({ error: 'Datos de pago incompletos' });
    }
    const secret = process.env.WOMPI_INTEGRITY_SECRET;
    if (!secret) {
      return res.status(500).json({ error: 'Configuración de pagos pendiente' });
    }
    const text = `${reference}${amountInCents}${currency}${secret}`;
    const signature = crypto.createHash('sha256').update(text).digest('hex');
    return res.status(200).json({ signature });
  } catch (_) {
    return res.status(500).json({ error: 'No fue posible preparar el pago' });
  }
};

