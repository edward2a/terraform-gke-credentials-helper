package main


import (
  "crypto"
  "crypto/rand"
  "crypto/rsa"
  "crypto/x509"
  "encoding/json"
  "encoding/pem"
  "log"
  "os"
  "time"
)


type GoogleCloudKey struct {
  Type string
  ProjectId string
  PrivateKeyId string
  PrivateKey string
  ClientEmail string
  ClientId string
  AuthUri string
  TokenUrl string
  AuthProviderX509CertUrl string
  ClientX509CertUrl string
}

type JwtHeader struct {
  alg string
  typ string
  kid string
}

type JwtClaims struct {
  iss string
  scope string
  aud string
  iat int64
  exp int64
}

type Jwt struct {
  header JwtHeader
  payload JwtClaims
  signature string
}

func loadGoogleCredentials() GoogleCloudKey {

  data := os.Getenv("GOOGLE_CLOUD_KEY")
  key_data := make(map[string]interface{})

  if data != "" {
    err := json.Unmarshal([]byte(data), &key_data)
    if err != nil { log.Fatalln(err) }
  } else {
    log.Fatalln("ERROR: Variable GOOGLE_CLOUD_KEY not present in environment or empty")
  }

  key := GoogleCloudKey{
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

  return key
}

func parsePem(key GoogleCloudKey) *rsa.PrivateKey {
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
  header, _ = json.Marshal(jwt.header)
  payload, _ = json.Marshal(jwt.payload)

  s_string := []byte(string(header) + "." + string(payload))
  signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, s_string)
  if err != nil { log.Fatalln(err) }
  jwt.signature = string(signature)
}

func createJwt(key *GoogleCloudKey) Jwt {
  t := time.Now().Unix()
  return Jwt{
    header: JwtHeader{
      alg:  "RS256",
      kid:  key.PrivateKeyId,
      typ:  "JWT",
    },
    payload: JwtClaims{
      iss:  key.ClientEmail,
      aud:  "https://oauth2.googleapis.com/token",
      iat:  t,
      exp:  t + 3600,
      scope: "https://www.googleapis.com/auth/cloud-platform",
    },
  }
}

func main() {
/*  var header []byte
  var payload []byte*/

  google_key := loadGoogleCredentials()
  log.Printf("Key: %+v", google_key)

  jwt := createJwt(&google_key)
/*
  header, err := json.Marshal(jwt.header)
  if err != nil { log.Fatalln(err) }

  payload, err = json.Marshal(jwt.payload)
  if err != nil { log.Fatalln(err) }
*/
  log.Println(jwt)
}
