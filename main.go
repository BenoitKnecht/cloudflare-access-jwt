package main

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	ctx    = context.Background()
	issuer = kingpin.Flag("issuer", "Cloudflare Access JWT issuer URL").
		PlaceHolder("https://NAME.cloudflareaccess.com").
		Required().
		URL()

	verifier *oidc.IDTokenVerifier
)

func verifyToken(w http.ResponseWriter, r *http.Request) {
	if jwt := r.Header.Get("Cf-Access-Jwt-Assertion"); len(jwt) > 0 {
		if token, err := verifier.Verify(r.Context(), jwt); err == nil {
			clientID := strings.TrimPrefix(r.URL.Path, "/")
			for _, audience := range token.Audience {
				if audience == clientID {
					reply(w, http.StatusOK, r, token)
					return
				}
			}
		}
	}

	reply(w, http.StatusUnauthorized, r, nil)
}

func reply(w http.ResponseWriter, status int, r *http.Request, token *oidc.IDToken) {
	w.WriteHeader(status)

	go func() {
		user := "-"
		if token != nil {
			var claims struct {
				Email      string `json:"email"`
				CommonName string `json:"common_name"`
			}
			if err := token.Claims(&claims); err == nil {
				if len(claims.Email) > 0 {
					user = claims.Email
				} else if len(claims.CommonName) > 0 {
					user = claims.CommonName
				}
			}
		}

		log.Printf(`%s - %s [%s] "%s %s %s" %d - "%s" "%s"`,
			r.Header.Get("CF-Connecting-IP"),
			user,
			time.Now().Format(time.RFC3339),
			r.Method,
			r.RequestURI,
			r.Proto,
			status,
			r.Header.Get("X-Original-Url"),
			r.UserAgent(),
		)
	}()
}

func main() {
	kingpin.Parse()
	log.SetFlags(0)

	keySet := oidc.NewRemoteKeySet(ctx, (*issuer).String()+"/cdn-cgi/access/certs")
	verifier = oidc.NewVerifier((*issuer).String(), keySet, &oidc.Config{SkipClientIDCheck: true})

	http.HandleFunc("/", verifyToken)
	http.ListenAndServe(":3000", nil)
}
