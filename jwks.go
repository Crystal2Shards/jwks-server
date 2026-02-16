package jwks

// JWKS returns all unexpired keys in JWKS format
func (km *KeyManager) JWKS() map[string]interface{} {
    keys := []interface{}{}
    for _, k := range km.Keys {
        if k.ExpiresAt.After(time.Now()) {
            keys = append(keys, k.ToJWK())
        }
    }
    return map[string]interface{}{
        "keys": keys,
    }
}
