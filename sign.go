package sign

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/url"
	"sort"
	"strings"
)

//微信支付计算签名的函数
func WeiXinpayCalcSign(mReq map[string]interface{}, key string) (sign string) {
	//STEP 1, 对key进行升序排序.
	sorted_keys := make([]string, 0)
	for k, _ := range mReq {
		sorted_keys = append(sorted_keys, k)
	}
	sort.Strings(sorted_keys)
	//STEP2, 对key=value的键值对用&连接起来，略过空值
	var signStrings string
	for _, k := range sorted_keys {
		value := fmt.Sprintf("%v", mReq[k])
		if value != "" {
			signStrings = signStrings + k + "=" + value + "&"
		}
	}
	//STEP3, 在键值对的最后加上key=API_KEY
	if key != "" {
		signStrings = signStrings + "key=" + key
	}
	//STEP4, 进行MD5签名并且将所有字符转为大写.
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(signStrings))
	return strings.ToUpper(hex.EncodeToString(md5Ctx.Sum(nil)))
}

func Sha1(str string) []byte {
	h1 := sha1.New()
	io.WriteString(h1, str)
	hashed := h1.Sum(nil)
	x := fmt.Sprintf(hex.EncodeToString(hashed))
	h2 := crypto.Hash.New(crypto.SHA1)
	h2.Write([]byte(x))
	return h2.Sum(nil)
}

func GetKeysAndValuesBySortKeys(urlValues url.Values) (values []string) {
	vLen := len(urlValues)
	if vLen <= 0 {
		return
	}
	// get keys
	keys := make([]string, vLen)
	i := 0
	for k := range urlValues {
		keys[i] = k
		i++
	}
	// sort keys
	sort.Sort(sort.StringSlice(keys))
	values = make([]string, vLen)
	for i, k := range keys {
		values[i] = fmt.Sprintf(`%s=%s`, k, urlValues.Get(k))
	}
	return
}

//apple pay 计算签名的函数
func SignApplepaySign(mReq map[string]interface{}, priv *rsa.PrivateKey) (sign string, err error) {
	//STEP 1, 对key进行升序排序.
	sorted_keys := make([]string, 0)
	for k, _ := range mReq {
		sorted_keys = append(sorted_keys, k)
	}
	sort.Strings(sorted_keys)
	//STEP2, 对key=value的键值对用&连接起来，略过空值
	var signStrings string
	for _, k := range sorted_keys {
		value := fmt.Sprintf("%v", mReq[k])
		if value != "" {
			signStrings = signStrings + k + "=" + value + "&"
		}
	}
	//STEP3, 签名
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, Sha1(signStrings))
	if err != nil {
		log.Printf("Error from signing: %s\n", err)
	}
	//STEP4, base64
	sign = string(base64.StdEncoding.EncodeToString(signature))
	return
}

// apple pay 验证签名
func VerifyApplepaySign(publicKey *rsa.PublicKey, values url.Values) error {
	// rsa verify
	sign := values.Get("signature")
	values.Del("signature")
	value := strings.Join(GetKeysAndValuesBySortKeys(values), "&")
	s, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		log.Println(err)
		return err
	}
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, Sha1(value), s)
}

//ali pay 计算签名的函数
func SignAlipaySign(privatekey *rsa.PrivateKey, params string) (sign string, err error) {
	// SignPKCS1v15 签名
	hash := sha1.New()
	io.WriteString(hash, params)
	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privatekey, crypto.SHA1, hashed)

	return url.QueryEscape(base64.StdEncoding.EncodeToString(signature)), err
}

// ali pay 验证签名
func VerifyAlipaySign(publicKey *rsa.PublicKey, values url.Values) error {
	// rsa verify
	sign := values.Get("sign")
	values.Del("sign")
	values.Del("sign_type")
	value := strings.Join(GetKeysAndValuesBySortKeys(values), "&")
	s, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}
	h := sha1.New()
	h.Write([]byte(value))
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA1, digest, s)
}
