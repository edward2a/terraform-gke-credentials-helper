package main


import (
  //"bytes"
  "crypto"
  "crypto/rand"
  "crypto/rsa"
  "crypto/sha256"
  "crypto/x509"
  "encoding/base64"
  "encoding/json"
  "encoding/pem"
  "io/ioutil"
  "log"
  "net/http"
  "net/url"
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


type JwtB64 struct {
  Header    []byte
  Payload   []byte
  Signature []byte
}


type Jwt struct {
  Header    JwtHeader `json:"header"`
  Payload   JwtClaims `json:"payload"`
  Signature []byte    `json:"signature"`
  b64       JwtB64
}


func byteAppender(inputs ...[]byte) *[]byte {
  var output []byte

  for _, arr := range inputs {
    for _, v := range arr {
      output = append(output, v)
    }
  }

  return &output
}


func loadGoogleCredentials() *GoogleCloudKey {

  data := os.Getenv("GOOGLE_CLOUD_KEY")

  var key GoogleCloudKey
  if data != "" {
    err := json.Unmarshal([]byte(data), &key)
    if err != nil { log.Fatalln(err) }
  } else {
    log.Fatalln("ERROR: Variable GOOGLE_CLOUD_KEY not present in environment or empty")
  }

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
  digest := sha256.Sum256([]byte(string(jwt.b64.Header) + "." + string(jwt.b64.Payload)))

  signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
  if err != nil { log.Fatalln(err) }

  jwt.Signature = signature
  jwt.b64.Signature = []byte(base64.RawURLEncoding.EncodeToString(signature))
}


func createJwt(key *GoogleCloudKey) *Jwt {
  t := time.Now().Unix()
  jwt := &Jwt{
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

  json_h, err := json.Marshal(jwt.Header)
  if err != nil { log.Fatalln(err) }

  json_p, err := json.Marshal(jwt.Payload)
  if err != nil { log.Fatalln(err) }

  jwt.b64.Header = []byte(base64.RawURLEncoding.EncodeToString(json_h))
  jwt.b64.Payload = []byte(base64.RawURLEncoding.EncodeToString(json_p))

  return jwt
}


func requestOauth2Token(jwt *Jwt) {
  separator := []byte(".")
  //body_p1 := "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion="
  assertion := byteAppender(jwt.b64.Header, separator, jwt.b64.Payload, separator, jwt.b64.Signature)
  //body_reader := bytes.NewReader(*body)

  /*
  resp := &http.Client{}
  //req, err := http.NewRequest("POST", "https://oauth2.googleapis.com/token", body_reader)
  req, err := http.NewRequest("POST", "https://oauth2.googleapis.com/token", nil)
  req.Form := url.Values{
    "grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
    "assertion":  {assertion}
  }*/

  resp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
    "grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
    "assertion":  {string(*assertion)},
  })
  if err != nil { log.Fatalln(err) }

  defer resp.Body.Close()
  resp_body, err := ioutil.ReadAll(resp.Body)
  if err != nil { log.Fatalln(err) }

  if resp.StatusCode != 200 {
    log.Fatalln(string(resp_body))
  }

  log.Println(string(resp_body))
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
  /*log.Println(google_key)
  log.Println(jwt)*/
  log.Println(string(jwt.b64.Header), string(jwt.b64.Payload), string(jwt.b64.Signature))

  requestOauth2Token(jwt)
}
