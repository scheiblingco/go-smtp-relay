FROM docker.io/library/golang:alpine as builder

ENV GO111MODULE=on

WORKDIR /build

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o smtp-relay .

FROM alpine

WORKDIR /app

COPY --from=builder /build/smtp-relay .
COPY --from=builder /build/config.example.json .

EXPOSE 2525

CMD ["/app/smtp-relay"]