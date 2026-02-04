# SEFAZ Proxy (mTLS)

Proxy simples para comunicação mTLS com a SEFAZ NFC-e.  
Deploy em **Railway**, **Render** ou **Fly.io**.

## Variáveis de ambiente

| Nome | Descrição |
|------|-----------|
| `PORT` | Porta HTTP (padrão 3000) |
| `PROXY_SECRET` | Token de autenticação (opcional) |

## Endpoints

### `POST /soap`

Recebe:
```json
{
  "url": "https://nfce.fazenda.sp.gov.br/ws/NFeAutorizacao4.asmx",
  "soapAction": "http://www.portalfiscal.inf.br/nfe/wsdl/NFeAutorizacao4/nfeAutorizacaoLote",
  "envelope": "<soap:Envelope>...</soap:Envelope>",
  "pfxBase64": "base64...",
  "pfxPassword": "senha"
}
```

Retorna:
```json
{
  "status": 200,
  "headers": { ... },
  "body": "<soap:Envelope>...</soap:Envelope>"
}
```

### `GET /health`

Health check.

---

## Deploy rápido (Railway)

1. Crie um novo projeto no Railway.
2. Conecte este diretório ou faça push para um repo.
3. Defina `PROXY_SECRET` nas variáveis de ambiente.
4. Após deploy, copie a URL (ex: `https://sefaz-proxy.up.railway.app`).
5. Configure essa URL na secret `SEFAZ_PROXY_URL` do seu projeto Lovable.
