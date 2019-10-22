FROM golang:1.13 as build
  
COPY . /go/src/github.com/BenoitKnecht/cloudflare-access-jwt
WORKDIR /go/src/github.com/BenoitKnecht/cloudflare-access-jwt

RUN CGO_ENABLED=0 go get .
RUN strip /go/bin/cloudflare-access-jwt

FROM gcr.io/distroless/static

COPY --from=build /go/bin/cloudflare-access-jwt /bin/

USER 23071

EXPOSE 3000

ENTRYPOINT ["cloudflare-access-jwt"]
