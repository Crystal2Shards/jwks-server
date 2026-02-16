package jwks

import (
    "crypto/rand"
    "crypto/rsa"
    "encoding/base64"
    "time"
)

// KeyPair holds a private/public RSA key, a kid, and an expiry
type KeyPair struct {
    PrivateKey *rsa.PrivateKey
    PublicKey  *rsa.PublicKey
    Kid        string
    ExpiresAt  time.Time
}

// KeyManager holds all keys
type KeyManager struct {
    Keys []*KeyPair
}

// NewKeyManager creates a key manager with one key
func NewKeyManager() *KeyManager {
    km := &KeyManager{}
    km.RotateKey()
    return km
}

// generateKid creates a random kid
func generateKid() string {
    b := make([]byte, 16)
    rand.Read(b)
    return base64.RawURLEncoding.EncodeToString(b)
}

// RotateKey generates a new key with expiry
func (km *KeyManager) RotateKey() {
    key, _ := rsa.GenerateKey(rand.Reader, 2048)
    km.Keys = append(km.Keys, &KeyPair{
        PrivateKey: key,
        PublicKey:  &key.PublicKey,
        Kid:        generateKid(),
        ExpiresAt:  time.Now().Add(5 * time.Minute),
    })
}

// GetActiveKey returns the first unexpired key
func (km *KeyManager) GetActiveKey() *KeyPair {
    for _, k := range km.Keys {
        if k.ExpiresAt.After(time.Now()) {
            return k
        }
    }
    km.RotateKey()
    return km.GetActiveKey()
}

// GetExpiredKey returns the first expired key
func (km *KeyManager) GetExpiredKey() *KeyPair {
    for _, k := range km.Keys {
        if k.ExpiresAt.Before(time.Now()) {
            return k
        }
    }
    return km.GetActiveKey() // fallback if none expired
}

// ToJWK converts KeyPair to JWK format
func (k *KeyPair) ToJWK() map[string]interface{} {
    n := base64.RawURLEncoding.EncodeToString(k.PublicKey.N.Bytes())
    e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}) // 65537

    return map[string]interface{}{
        "kty": "RSA",
        "kid": k.Kid,
        "use": "sig",
        "alg": "RS256",
        "n":   n,
        "e":   e,
    }
}
