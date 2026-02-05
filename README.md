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
