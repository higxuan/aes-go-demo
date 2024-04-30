package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
)

func main() {
	// 获取命令行参数
	args := os.Args
	if len(args) < 5 {
		fmt.Println("Usage: go run main.go <plaintext> <key> <iv> <encrypt|decrypt>")
		return
	}

	// 获取明文、密钥和 IV
	plaintext := args[1]
	key := args[2]
	iv := args[3]
	encryptOrDecrypt := args[4]
	// 加密
	if encryptOrDecrypt == "encrypt" {
		encrypted, err := encrypt_content([]byte(plaintext), []byte(key), []byte(iv))
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Println(string(encrypted))
	}

	if encryptOrDecrypt == "decrypt" {
		decrypted, err := decrypt_content([]byte(plaintext), []byte(key), []byte(iv))
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		fmt.Println(string(decrypted))
	}

}

func encrypt_content(src, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	if 0 == len(src) {
		return []byte{}, errors.New("AES/CBC/PKCS5PADDING encrypt failed, src empty")
	}

	ecbEncoder := cipher.NewCBCEncrypter(block, iv)
	content := PKCS5_padding(src, block.BlockSize())
	if len(content)%aes.BlockSize != 0 {
		return []byte{}, errors.New("AES/CBC/PKCS5PADDING encrypt content not a multiple of the block size")
	}

	encrypted := make([]byte, len(content))
	ecbEncoder.CryptBlocks(encrypted, content)

	if err != nil {
		return []byte{}, err
	}
	base64Str := base64.StdEncoding.EncodeToString(encrypted)
	urlEncodeStr := url.QueryEscape(base64Str)
	return []byte(urlEncodeStr), nil
}

func decrypt_content(encrypted, key, iv []byte) (decryptContent []byte, decryptError error) {
	urlDecode, err := url.QueryUnescape(string(encrypted))
	if err != nil {
		return []byte{}, err
	}

	plainContent, err := base64.StdEncoding.DecodeString(urlDecode)

	if err != nil {
		return []byte{}, err
	}

	decryptContent = []byte{}

	block, err := aes.NewCipher(key)
	if err != nil {
		decryptError = err
		return
	}

	if 0 == len(plainContent) {
		decryptError = errors.New("AES/CBC/PKCS5PADDING decrypt failed, src empty")
		return
	}

	ecbDecoder := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(plainContent))
	ecbDecoder.CryptBlocks(decrypted, plainContent)

	decryptContent = PKCS5_trimming(decrypted)

	if err != nil {
		return []byte{}, err
	}
	return decryptContent, nil

}

func PKCS5_padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func PKCS5_trimming(encryptText []byte) []byte {
	padding := encryptText[len(encryptText)-1]
	return encryptText[:len(encryptText)-int(padding)]
}
