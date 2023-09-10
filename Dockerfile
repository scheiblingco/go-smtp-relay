FROM docker.io/library/golang:alpine as builder

ENV GO111MODULE=on

WORKDIR /build

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o smtp-relay .

FROM scratch

COPY --from=builder /build/smtp-relay /smtp-relay
COPY --from=builder /build/config.example.json /config.json

RUN apk --no-cache add ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/cache/apk/* 

EXPOSE 2525

CMD ["/smtp-relay"]