package corpwechat

import (
	"encoding/json"
	"github.com/segmentfault/pacman/log"
	"net/http"
	"net/url"
	"time"
)

type Token struct {
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// Client get client
func Client(proxyIP string) *http.Client {
	proxyURL, err := url.Parse(proxyIP)
	if err != nil {
		log.Error("proxyIP failed", err)
		return nil
	}
	httpClient := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL)},
	}
	// 设置5秒过时
	httpClient.Timeout = 5 * time.Second
	return httpClient
}

// TokenFromCorpWechat 获取token
func (g *Connector) TokenFromCorpWechat() {
	// 1.get http client
	httpClient := Client(g.Config.ProxyIP)

	// 2.Get access_token of enterprise WeChat exit via code. [GET Method]
	tokenURL := UrlConfig{
		CorpID:     g.Config.AppID,
		Corpsecret: g.Config.CorpSecret,
		URL:        TOKEN_URL,
	}

	buildURL := tokenURL.BuildURL()
	tokenResp, err := httpClient.Get(buildURL)
	if err != nil {
		log.Errorf("failed getting token: %s", err)
		return
	}
	var tokenData = &Token{}

	err = json.NewDecoder(tokenResp.Body).Decode(tokenData)

	if err != nil {
		log.Errorf("token data parsing failed: %s", tokenResp.Body)
		return
	}
	log.Infof("access_token = %s", tokenData.AccessToken)

	// 存入tokenCache
	tokenCache = tokenData.AccessToken
	if tokenCache != "" {
		log.Debugf("tokenCache save success!")
	}
	defer tokenResp.Body.Close()
}

// update 定时更新token
func (g *Connector) update() {
	ticker := time.NewTicker(7000 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		g.TokenFromCorpWechat()
	}
}
