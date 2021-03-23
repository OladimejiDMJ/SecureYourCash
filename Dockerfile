FROM python:3.8-slim
RUN mkdir /app
WORKDIR /app
COPY requirements.txt /app
RUN pip3 install -r requirements.txt
COPY . /app
EXPOSE 80
ENTRYPOINT ["gunicorn", "--config", "gunicorn_config.py", "wsgi:app"]
