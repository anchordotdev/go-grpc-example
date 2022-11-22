FROM golang:alpine AS builder

WORKDIR /app
COPY . .

RUN go build -o /bin/pong-server ./server

FROM alpine

COPY --from=builder /bin/pong-server /bin/pong-server

EXPOSE 4433

CMD /bin/pong-server
