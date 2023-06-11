FROM alpine:edge
RUN apk update
RUN apk add python3 py3-pip

WORKDIR /client
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY . .

CMD ["python3","app.py"]