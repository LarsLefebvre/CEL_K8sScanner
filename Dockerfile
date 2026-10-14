FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kscan ./cmd/kscan

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/kscan /kscan
USER 65532:65532
ENTRYPOINT ["/kscan"]
CMD ["serve"]
