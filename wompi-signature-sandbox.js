const crypto = require('crypto');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });
  try {
    const { reference, amountInCents, currency } = req.body || {};
    if (!reference || !Number.isInteger(amountInCents) || amountInCents <= 0 || currency !== 'COP') {
      return res.status(400).json({ error: 'Datos de pago incompletos' });
    }
    const secret = process.env.WOMPI_INTEGRITY_SECRET_SANDBOX;
    if (!secret) return res.status(500).json({ error: 'Configuración de Sandbox pendiente' });
    const signature = crypto
      .createHash('sha256')
      .update(`${reference}${amountInCents}${currency}${secret}`)
      .digest('hex');
    return res.status(200).json({ signature });
  } catch (_) {
    return res.status(400).json({ error: 'Solicitud no válida' });
  }
};
