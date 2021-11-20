package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	aesCMAC "github.com/aead/cmac/aes"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

const (
	toggleCommand = "88"
	lockCommand   = "82"
	unlockCommand = "83"
)

var applicationName = base64.StdEncoding.EncodeToString([]byte("sesame3-proxy"))

func main() {
	if err := godotenv.Load(); err != nil {
		panic(err)
	}

	port := os.Getenv("PORT")

	apiKey := os.Getenv("API_KEY")

	uuid1 := os.Getenv("SESAME3_UUID1")
	uuid2 := os.Getenv("SESAME3_UUID2")

	sign1, err := calculateSign(os.Getenv("SESAME3_SECRET_KEY1"))
	if err != nil {
		panic(err)
	}

	sign2, err := calculateSign(os.Getenv("SESAME3_SECRET_KEY2"))
	if err != nil {
		panic(err)
	}

	engine := gin.Default()
	engine.POST("/lock", func(c *gin.Context) {
		requestCommand(apiKey, uuid1, lockCommand, sign1)
		requestCommand(apiKey, uuid2, lockCommand, sign2)
		c.String(http.StatusOK, "OK")
	})
	engine.POST("/unlock", func(c *gin.Context) {
		requestCommand(apiKey, uuid1, unlockCommand, sign1)
		requestCommand(apiKey, uuid2, unlockCommand, sign2)
		c.String(http.StatusOK, "OK")
	})

	engine.Run("0.0.0.0:" + port)
}

func calculateSign(secretKey string) ([]byte, error) {
	key, err := hex.DecodeString(secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret key: %w", err)
	}

	messageBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(messageBuffer, uint32(time.Now().Unix()))

	sign, err := aesCMAC.Sum(messageBuffer[1:4], key, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate sign: %w", err)
	}

	return sign, nil
}

func requestCommand(apiKey, uuid, command string, sign []byte) error {
	data, err := json.Marshal(map[string]string{
		"cmd":     command,
		"history": applicationName,
		"sign":    hex.EncodeToString(sign),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	request, _ := http.NewRequest(http.MethodPost, "https://app.candyhouse.co/api/sesame2/"+uuid+"/cmd", bytes.NewBuffer(data))
	request.Header.Set("x-api-key", apiKey)

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer response.Body.Close()

	return nil
}
