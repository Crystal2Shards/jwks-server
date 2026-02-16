package tests

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "jwks-server/jwks"
    "jwks-server/handlers"
)

func TestAuth(t *testing.T) {
    km := jwks.NewKeyManager()
    rr := httptest.NewRecorder()
    req := httptest.NewRequest("POST", "/auth", nil)

    handler := handlers.AuthHandler(km)
    handler(rr, req)

    if rr.Code != http.StatusOK {
        t.Fatalf("status %d", rr.Code)
    }

    data := map[string]string{}
    json.Unmarshal(rr.Body.Bytes(), &data)
    if data["token"] == "" {
        t.Fatalf("no token issued")
    }
}
