package handlers

import (
    "encoding/json"
    "net/http"
    "jwks-server/jwks"
)

func JWKSHandler(km *jwks.KeyManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        jwksData := km.JWKS()
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(jwksData)
    }
}
