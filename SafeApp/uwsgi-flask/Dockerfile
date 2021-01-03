FROM python:3.7-alpine
WORKDIR /var/www

ENV FLASK_APP app/app.py
ENV FLASK_RUN_HOST 0.0.0.0

RUN apk add --no-cache gcc musl-dev linux-headers

COPY uwsgi.ini uwsgi.ini
COPY wsgi.py wsgi.py
COPY requirements.txt requirements.txt
# COPY db_setup.py .

RUN pip install -r requirements.txt

COPY /app /app

# RUN python3 db_setup.py
# RUN chmod a+w /app/data.sqlite3

CMD ["uwsgi", "--ini", "uwsgi.ini"]