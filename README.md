# Sisteminha de Controle

Web app simples para registrar disparos diarios, aceites e encaminhamentos por vendedor.

## Requisitos
- Python 3.10+

## Instalar e rodar localmente
```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
set FLASK_APP=app.py
flask run
```

## Criar usuarios
```bash
set FLASK_APP=app.py
flask create-user
```

- `editor` pode lancar relatorios e gerenciar vendedores.
- `viewer` apenas visualiza e exporta.

## Cadastrar vendedores
- Pela tela `Vendedores` (usuario editor)
- Ou via CLI:
```bash
set FLASK_APP=app.py
flask create-vendor
```

### Seed inicial (lista fornecida)
```bash
set FLASK_APP=app.py
flask seed-vendors
```

## Exportacoes
- Excel e PDF a partir do dashboard.

## Observacoes
- O SQLite fica em `instance/app.db`.
- Defina `SECRET_KEY` em producao.

## Docker (exemplo)
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
ENV FLASK_APP=app.py
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
```

## Nginx Proxy + LetsEncrypt (stack_nginx-proxy)
Se voce ja usa `jwilder/nginx-proxy` + `letsencrypt-nginx-proxy-companion`:
- ajuste `VIRTUAL_HOST`, `LETSENCRYPT_HOST` e `LETSENCRYPT_EMAIL` em `docker-compose.yml`
- a rede externa esta configurada como `stack_nginx-proxy`

## Automacao via n8n (Webhook)
O sistema aceita um POST para criar/atualizar o relatorio do dia.

### Variaveis de ambiente
- `API_TOKEN`: token compartilhado (obrigatorio)
- `API_USER`: username de um usuario `editor` (opcional). Se nao definir, usa o primeiro editor cadastrado.

### Endpoint
`POST /api/n8n/report`

Header:
- `Authorization: Bearer <API_TOKEN>` ou `X-API-Key: <API_TOKEN>`

Payload exemplo:
```json
{
  "date": "2026-02-05",
  "total_sent": 120,
  "total_accepted": 30,
  "allocations": [
    {"email": "comercial1@abmix.com.br", "count": 10},
    {"email": "comercial2@abmix.com.br", "count": 20}
  ],
  "notes": "Relatorio automatico do n8n"
}
```

Regras:
- Se `total_accepted` nao vier, ele sera a soma das alocacoes.
- A soma das alocacoes deve bater com `total_accepted`.
- `total_accepted` nao pode ser maior que `total_sent`.

## Email diario (Resend)
Envie o relatorio por email logo apos receber o webhook do n8n.

Variaveis:
- `RESEND_API_KEY`: chave da API do Resend
- `RESEND_FROM`: remetente verificado (ex: `relatorio@abmix.tech`)
- `RESEND_TO`: lista de emails separados por virgula
