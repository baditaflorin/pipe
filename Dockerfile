FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/app .

FROM alpine:3.22
RUN apk upgrade --no-cache
RUN apk add --no-cache ca-certificates wget tini \
 && addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY --from=builder /out/app /app/app
USER app
EXPOSE 18272
ENV PORT=18272
HEALTHCHECK --interval=60s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:${PORT}/health >/dev/null || exit 1
ENTRYPOINT ["/sbin/tini","--"]
CMD ["/app/app"]
