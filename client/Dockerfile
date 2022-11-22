FROM golang:alpine AS builder

WORKDIR /app
COPY . .

RUN go build -o /bin/ping-client ./client

FROM alpine

COPY --from=builder /bin/ping-client /bin/ping-client

CMD /bin/ping-client
