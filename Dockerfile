# Imagem Nextec do gerador de clientes (mesmo codigo do rdgen oficial + padroes Nextec por variavel de ambiente).
FROM python:3.13-alpine

LABEL org.opencontainers.image.source="https://github.com/Sou-Nextec/rdgen"

RUN adduser -D user
WORKDIR /opt/rdgen

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=user:user . .
# pastas que o gerador grava (montadas como volume na stack); o banco fica em data/
RUN mkdir -p exe png temp_zips data && chown -R user:user /opt/rdgen
USER user

ENV PYTHONUNBUFFERED=1 \
    DB_PATH=/opt/rdgen/data/db.sqlite3

EXPOSE 8000

# start-period: o primeiro minuto (migrate + gunicorn subindo) nao conta como falha
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 CMD wget -q -O /dev/null http://127.0.0.1:8000/ || exit 1

# migra o banco (no volume) e sobe o gunicorn
CMD ["sh", "-c", "python manage.py migrate --noinput && exec gunicorn -c gunicorn.conf.py rdgen.wsgi:application"]
