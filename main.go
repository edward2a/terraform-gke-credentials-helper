package main


import (
  "crypto"
  "crypto/rand"
  "crypto/rsa"
  "crypto/sha256"
  "crypto/x509"
  //"encoding/base64"
  "encoding/json"
  "encoding/pem"
  "log"
  "os"
  "time"
)


type GoogleCloudKey struct {
  Type                    string `json:"type"`
  ProjectId               string `json:"project_id"`
  PrivateKeyId            string `json:"private_key_id"`
  PrivateKey              string `json:"private_key"`
  ClientEmail             string `json:"client_email"`
  ClientId                string `json:"client_id"`
  AuthUri                 string `json:"auth_uri"`
  TokenUrl                string `json:"token_url"`
  AuthProviderX509CertUrl string `json:"auth_provider_x509_cert_url"`
  ClientX509CertUrl       string `json:"client_x509_cert_url"`
}

type JwtHeader struct {
  Alg string `json:"alg"`
  Typ string `json:"typ"`
  Kid string `json:"kid"`
}

type JwtClaims struct {
  Iss   string  `json:"iss"`
  Scope string  `json:"scope"`
  Aud   string  `json:"aud"`
  Iat   int64   `json:"iat"`
  Exp   int64   `json:"exp"`
}

type Jwt struct {
  Header    JwtHeader `json:"header"`
  Payload   JwtClaims `json:"payload"`
  Signature string    `json:"signature"`
}

func loadGoogleCredentials() *GoogleCloudKey {

  data := os.Getenv("GOOGLE_CLOUD_KEY")
  //key_data := make(map[string]interface{})

  var key GoogleCloudKey
  if data != "" {
    err := json.Unmarshal([]byte(data), &key)
    if err != nil { log.Fatalln(err) }
  } else {
    log.Fatalln("ERROR: Variable GOOGLE_CLOUD_KEY not present in environment or empty")
  }

/*
  key := &GoogleCloudKey{
    Type:                     key_data["type"].(string),
    ProjectId:                key_data["project_id"].(string),
    PrivateKeyId:             key_data["private_key_id"].(string),
    PrivateKey:               key_data["private_key"].(string),
    ClientEmail:              key_data["client_email"].(string),
    ClientId:                 key_data["client_id"].(string),
    AuthUri:                  key_data["auth_uri"].(string),
    TokenUrl:                 key_data["token_uri"].(string),
    AuthProviderX509CertUrl:  key_data["auth_provider_x509_cert_url"].(string),
    ClientX509CertUrl:        key_data["client_x509_cert_url"].(string),
  }
*/
  return &key
}

func parsePem(key *GoogleCloudKey) *rsa.PrivateKey {
  var k interface{}

  decoded, _ := pem.Decode([]byte(key.PrivateKey))
  if decoded == nil { log.Fatalln("ERROR: INVALID KEY DATA") }

  k, err := x509.ParsePKCS8PrivateKey(decoded.Bytes)
  if err != nil { log.Fatalln(err) }

  return k.(*rsa.PrivateKey)
}

func signJwtRS256(jwt *Jwt, key *rsa.PrivateKey) {
  var header []byte
  var payload []byte
  header, _ = json.Marshal(jwt.Header)
  payload, _ = json.Marshal(jwt.Payload)

  s_string := sha256.Sum256([]byte(string(header) + "." + string(payload)))
  signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, s_string[:])
  if err != nil { log.Fatalln(err) }
  jwt.Signature = string(signature)
}

func createJwt(key *GoogleCloudKey) *Jwt {
  t := time.Now().Unix()
  return &Jwt{
    Header: JwtHeader{
      Alg:  "RS256",
      Kid:  key.PrivateKeyId,
      Typ:  "JWT",
    },
    Payload: JwtClaims{
      Iss:  key.ClientEmail,
      Aud:  "https://oauth2.googleapis.com/token",
      Iat:  t,
      Exp:  t + 3600,
      Scope: "https://www.googleapis.com/auth/cloud-platform",
    },
  }
}

func main() {

  google_key := loadGoogleCredentials()
  //log.Printf("Key: %+v", google_key)

  jwt := createJwt(google_key)
  signJwtRS256(jwt, parsePem(google_key))

  /*
  var header []byte
  var payload []byte
  var err error
  header, err = json.Marshal(jwt.Header)
  if err != nil { log.Fatalln(err) }
  payload, err = json.Marshal(jwt.Payload)
  if err != nil { log.Fatalln(err) }


  //h, _ := json.Marshal(jwt)
  //log.Println(string(h))
  //log.Println(string(header), string(payload))
  */
  log.Println(google_key)
  log.Println(jwt)
}
