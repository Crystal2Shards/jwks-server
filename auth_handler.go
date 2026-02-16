package handlers

import (
    "net/http"
    "time"
    "github.com/golang-jwt/jwt/v5"
    "jwks-server/jwks"
)

func AuthHandler(km *jwks.KeyManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var key *jwks.KeyPair
        if r.URL.Query().Has("expired") {
            key = km.GetExpiredKey()
        } else {
            key = km.GetActiveKey()
        }

        token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
            "user": "fake-user",
            "exp":  key.ExpiresAt.Unix(),
        })

        token.Header["kid"] = key.Kid

        signed, _ := token.SignedString(key.PrivateKey)

        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"token":"` + signed + `"}`))
    }
}
