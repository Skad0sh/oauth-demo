FROM alpine:edge
RUN apk update
RUN apk add nodejs npm

WORKDIR /server
COPY package.json .
RUN npm install
COPY . .

CMD ["node","app.js"]