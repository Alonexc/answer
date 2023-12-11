package corpwechat

import (
	"bytes"
	"github.com/segmentfault/pacman/log"
	"net/url"
	"strings"
)

const (
	USER_ID_URL     = "https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo"
	TOKEN_URL       = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
	USER_INFO_URL   = "https://qyapi.weixin.qq.com/cgi-bin/user/get"
	SEND_WECHAT_URL = "https://qyapi.weixin.qq.com/cgi-bin/message/send"
)

type UrlConfig struct {
	AccessToken string
	Code        string
	CorpID      string
	Corpsecret  string
	Userid      string
	URL         string
}

// BuildURL build url
func (u *UrlConfig) BuildURL() string {
	var buffer bytes.Buffer
	buffer.WriteString(u.URL)
	if u.AccessToken != "" && u.Code != "" {
		v := url.Values{
			"access_token": {u.AccessToken},
			"code":         {u.Code},
		}
		return Contains(u, buffer, v)
	}

	if u.CorpID != "" && u.Corpsecret != "" {
		v := url.Values{
			"corpid":     {u.CorpID},
			"corpsecret": {u.Corpsecret},
		}
		return Contains(u, buffer, v)
	}

	if u.AccessToken != "" && u.Userid != "" {
		v := url.Values{
			"access_token": {u.AccessToken},
			"userid":       {u.Userid},
		}
		return Contains(u, buffer, v)
	}
	if u.AccessToken != "" && u.Code == "" && u.Userid == "" {
		v := url.Values{
			"access_token": {u.AccessToken},
		}
		return Contains(u, buffer, v)
	}

	log.Error("Cannot concatenate this URL.")
	return ""
}

func Contains(u *UrlConfig, buffer bytes.Buffer, v url.Values) string {
	if strings.Contains(u.URL, "?") {
		buffer.WriteByte('&')
	} else {
		buffer.WriteByte('?')
	}
	buffer.WriteString(v.Encode())
	return buffer.String()
}

func (c *Config) AuthCodeURL(state string) string {
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)
	v := url.Values{
		"login_type": {"CorpApp"},
		"appid":      {c.AppID},
		"agentid":    {c.AgentID},
	}
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}

	if state != "" {
		// TODO(light): Docs say never to omit state; don't allow empty.
		v.Set("state", state)
	}

	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	log.Infof("oauthURL=%s", buf.String())
	return buf.String()
}
