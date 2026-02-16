package tests

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "jwks-server/jwks"
    "jwks-server/handlers"
)

func TestJWKS(t *testing.T) {
    km := jwks.NewKeyManager()
    rr := httptest.NewRecorder()
    req := httptest.NewRequest("GET", "/jwks.json", nil)

    handler := handlers.JWKSHandler(km)
    handler(rr, req)

    if rr.Code != http.StatusOK {
        t.Fatalf("status %d", rr.Code)
    }

    data := map[string]interface{}{}
    json.Unmarshal(rr.Body.Bytes(), &data)

    if len(data["keys"].([]interface{})) == 0 {
        t.Fatalf("JWKS returned no keys")
    }
}
