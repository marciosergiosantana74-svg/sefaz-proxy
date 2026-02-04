/**
 * Proxy mTLS para SEFAZ NFC-e (SP).
 * Deploy em Railway/Render/Fly.io.
 * 
 * Variáveis de ambiente (opcional):
 *   PROXY_SECRET - Token de autenticação para proteger o endpoint.
 */

require('dotenv').config();
const https = require('https');
const express = require('express');
const forge = require('node-forge');

const app = express();
app.use(express.json({ limit: '2mb' }));

const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.PROXY_SECRET || '';

// Middleware simples de autenticação
function authMiddleware(req, res, next) {
  if (PROXY_SECRET) {
    const authHeader = req.headers['x-proxy-secret'] || '';
    if (authHeader !== PROXY_SECRET) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  }
  next();
}

/**
 * Extrai cert/key/chain de um PFX base64.
 */
function parsePfx(base64Pfx, password) {
  const p12Der = forge.util.decode64(base64Pfx);
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const keyBag = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0];
  if (!keyBag || !keyBag.key) throw new Error('Private key not found');

  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const allCerts = certBags[forge.pki.oids.certBag] || [];
  if (!allCerts.length) throw new Error('Certificate not found');

  let endEntityCert = null;
  const chainCerts = [];

  for (const bag of allCerts) {
    if (!bag.cert) continue;
    try {
      const certPubPem = forge.pki.publicKeyToPem(bag.cert.publicKey);
      const keyPubPem = forge.pki.publicKeyToPem(
        forge.pki.setRsaPublicKey(keyBag.key.n, keyBag.key.e)
      );
      if (certPubPem === keyPubPem) {
        endEntityCert = bag.cert;
      } else {
        chainCerts.push(bag.cert);
      }
    } catch {
      chainCerts.push(bag.cert);
    }
  }
  if (!endEntityCert) endEntityCert = allCerts[0].cert;

  const certPem = forge.pki.certificateToPem(endEntityCert);
  const keyPem = forge.pki.privateKeyToPem(keyBag.key);
  const chainPem = chainCerts.map((c) => forge.pki.certificateToPem(c)).join('\n');

  return { certPem, keyPem, chainPem };
}

/**
 * POST /soap
 * Body:
 *   url: URL do webservice SEFAZ
 *   soapAction: SOAPAction header
 *   envelope: corpo SOAP (string)
 *   pfxBase64: certificado PFX em base64
 *   pfxPassword: senha do PFX
 */
app.post('/soap', authMiddleware, async (req, res) => {
  const { url, soapAction, envelope, pfxBase64, pfxPassword } = req.body || {};

  if (!url || !envelope || !pfxBase64) {
    return res.status(400).json({ error: 'Missing required fields: url, envelope, pfxBase64' });
  }

  try {
    const { certPem, keyPem, chainPem } = parsePfx(pfxBase64, pfxPassword || '');

    const parsed = new URL(url);

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      servername: parsed.hostname,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
      cert: certPem + '\n' + chainPem,
      key: keyPem,
      rejectUnauthorized: false, // Ignora verificação de CA do servidor SEFAZ
      headers: {
        'Content-Type': 'application/soap+xml; charset=utf-8',
        'SOAPAction': soapAction || '',
        'Connection': 'close',
        'User-Agent': 'SefazProxy/1.0',
        'Content-Length': Buffer.byteLength(envelope, 'utf8'),
      },
    };

    const sefazReq = https.request(options, (sefazRes) => {
      let body = '';
      sefazRes.on('data', (chunk) => (body += chunk));
      sefazRes.on('end', () => {
        res.status(sefazRes.statusCode || 200).json({
          status: sefazRes.statusCode,
          headers: sefazRes.headers,
          body,
        });
      });
    });

    sefazReq.on('error', (e) => {
      console.error('SEFAZ request error:', e);
      res.status(502).json({ error: e.message });
    });

    sefazReq.setTimeout(30000, () => {
      sefazReq.destroy(new Error('Timeout'));
    });

    sefazReq.write(envelope);
    sefazReq.end();
  } catch (err) {
    console.error('Proxy error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`SEFAZ Proxy running on port ${PORT}`);
});
