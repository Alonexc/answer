package corpwechat

import (
	"bytes"
	"context"
	"corpwechat/i18n"
	"encoding/json"
	"fmt"
	"github.com/answerdev/answer/plugin"
	"github.com/segmentfault/pacman/log"
	"strconv"
	"strings"
	"time"
)

const (
	HEADER_WEBANK_NOTICE = "We开发者社区消息:\n"
	WEBANK_LINK_NOTICE   = "\n请访问<a href=\"http://developers.weoa.com/users/notifications/inbox\">开发者社区</a>进行查看"
)

// tokenCache 定义一个string存储token信息
var tokenCache string

type Connector struct {
	Config *ConnectorConfig
}

type ConnectorConfig struct {
	AppID       string `json:"app_id"`
	AgentID     string `json:"agent_id"`
	CorpSecret  string `json:"corp_secret"`
	RedirectURI string `json:"redirect_uri"`
	ProxyIP     string `json:"proxy_ip"`
}

func init() {
	connector = &Connector{
		Config: &ConnectorConfig{},
	}
	plugin.Register(connector)
}
func GetConnector() *Connector {
	return connector
}

var connector *Connector

func (g *Connector) Info() plugin.Info {
	return plugin.Info{
		Name:        plugin.MakeTranslator(i18n.InfoName),
		SlugName:    "corpwechat_connector",
		Description: plugin.MakeTranslator(i18n.InfoDescription),
		Author:      "alonexc",
		Version:     "0.0.1",
		Link:        "",
	}
}

func (g *Connector) ConnectorLogoSVG() string {
	return ""
}

func (g *Connector) ConnectorName() plugin.Translator {
	return plugin.MakeTranslator(i18n.ConnectorName)
}

func (g *Connector) ConnectorSlugName() string {
	return "corpwechat"
}

// ConnectorSender Constructing a code-sweeping login address
func (g *Connector) ConnectorSender(ctx *plugin.GinContext, receiverURL string) (redirectURL string) {
	oauthConfig := &Config{
		AppID:   g.Config.AppID,
		AgentID: g.Config.AgentID,
		Endpoint: Endpoint{
			AuthURL: "https://login.work.weixin.qq.com/wwlogin/sso/login",
		},
		RedirectURL: g.Config.RedirectURI,
	}
	return oauthConfig.AuthCodeURL("WWLogin")
}

// ConnectorReceiver Get the code and get the token according to the callback address,
// as well as the user's info
func (g *Connector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (userInfo plugin.ExternalLoginUserInfo, err error) {
	code := ctx.Query("code")
	// http client
	client := Client(g.Config.ProxyIP)
	client.Timeout = 15 * time.Second
	// 1.Get token
	accessToken := tokenCache
	log.Infof("ConnectorReceiver accessToken=%s", accessToken)

	if accessToken == "" {
		log.Info("accessToken is nil")
		return
	}

	// 2.Get userid by access_token and code
	authUrl := UrlConfig{
		AccessToken: accessToken,
		Code:        code,
		URL:         USER_ID_URL,
	}
	userIDResp, err := client.Get(authUrl.BuildURL())
	if err != nil {
		log.Errorf("get userID failed: %s", err)
		return
	}
	err = json.NewDecoder(userIDResp.Body).Decode(&userIDData)
	if err != nil {
		log.Errorf("userID data parsing failed: %s", err)
		return
	}
	log.Infof(fmt.Sprintf("UserID = %s, OpenID = %s", userIDData.UserID, userIDData.OpenID))
	userIDResp.Body.Close()
	// 3.Get user info by access_token and userid
	userInfoUrl := UrlConfig{
		AccessToken: accessToken,
		Userid:      userIDData.UserID,
		URL:         USER_INFO_URL,
	}
	userInfoResp, err := client.Get(userInfoUrl.BuildURL())
	if err != nil {
		log.Errorf("get user info failed: %s", err)
		return
	}
	err = json.NewDecoder(userInfoResp.Body).Decode(&userInfoData)
	if err != nil {
		log.Errorf("user infoData parsing failed: %s", err)
		return
	}
	log.Infof("UserID = %s, Name = %s, Email = %s, Avatar = %s",
		userInfoData.UserID, userInfoData.Name, userInfoData.Email, userInfoData.Avatar)
	userInfoResp.Body.Close()

	// data conversion
	metaInfo, _ := json.Marshal(userInfoResp)
	userInfo = plugin.ExternalLoginUserInfo{
		ExternalID:  fmt.Sprintf("%s", userInfoData.UserID),
		DisplayName: userInfoData.UserID,
		Username:    userInfoData.UserID,
		Email:       strings.Join([]string{userInfoData.UserID, "webank.com"}, "@"),
		MetaInfo:    string(metaInfo),
		Avatar:      userInfoData.Avatar,
	}

	log.Infof("UserID = %s, Name = %s, Email = %s, Avatar = %s",
		userInfo.ExternalID, userInfo.Username, userInfo.Email, userInfo.Avatar)

	return userInfo, nil
}

func (g *Connector) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "app_id",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigAppIDTitle),
			Description: plugin.MakeTranslator(i18n.ConfigAppIDDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.AppID,
		},
		{
			Name:        "agent_id",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigAgentIDTitle),
			Description: plugin.MakeTranslator(i18n.ConfigAgentIDDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.AgentID,
		},
		{
			Name:        "corp_secret",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigCorpSecretTitle),
			Description: plugin.MakeTranslator(i18n.ConfigCorpSecretDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.CorpSecret,
		},
		{
			Name:        "redirect_uri",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigRedirectURITitle),
			Description: plugin.MakeTranslator(i18n.ConfigRedirectURIDescription),
			Required:    false,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.RedirectURI,
		},
		{
			Name:        "proxy_ip",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigProxyIPTitle),
			Description: plugin.MakeTranslator(i18n.ConfigProxyIPDescription),
			Required:    false,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: g.Config.ProxyIP,
		},
	}
}

var isStart = false

func (g *Connector) ConfigReceiver(config []byte) error {
	c := &ConnectorConfig{}
	_ = json.Unmarshal(config, c)
	g.Config = c
	g.TokenFromCorpWechat()
	if !isStart {
		go func() {
			isStart = true
			g.update()
		}()
	}
	return nil
}

var userIDData struct {
	ErrCode        int    `json:"errcode"`
	ErrMsg         string `json:"errmsg"`
	UserID         string `json:"userid"`
	OpenID         string `json:"openid"`
	UserTicket     string `json:"user_ticket"`
	ExternalUserID string `json:"external_userid"`
}

var userInfoData struct {
	UserID    string `json:"userid"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Avatar    string `json:"avatar"`
	Position  string `json:"position"`
	Gender    string `json:"gender"`
	Telephone string `json:"telephone"`
	Alias     string `json:"alias"`
}

type Config struct {
	// AppID
	AppID string
	// AgentID
	AgentID string
	// CropSecret
	CropSecret string
	// Endpoint url
	Endpoint Endpoint
	// RedirectURL
	RedirectURL string
	// ProxyIP
	ProxyIP string
}

type Endpoint struct {
	AuthURL     string
	TokenURL    string
	UserIDURL   string
	UserInfoURL string
}

// MailNotice
func (g *Connector) MailNotice(ctx context.Context, touser string,
	displayName string, questionTitle string, sign int) {
	log.Infof("started send MailNotice to corpwechat")
	// client
	client := Client(g.Config.ProxyIP)

	// 1.Get access_token from cache
	accessToken := tokenCache

	if accessToken == "" {
		log.Errorf("accessToken is nil")
		return
	}

	log.Infof("Mail Notice tokenCache = %s", tokenCache)

	// 2.Send a message to the enterprise WeChat. [POST Method]
	var Content = ""
	// content
	if sign == 0 {
		Content = HEADER_WEBANK_NOTICE + "您关注的标签有新的提问: " + questionTitle + WEBANK_LINK_NOTICE
	}
	if sign == 1 {
		Content = HEADER_WEBANK_NOTICE + displayName + "评论了问题: " + questionTitle + WEBANK_LINK_NOTICE
	}
	if sign == 2 {
		Content = HEADER_WEBANK_NOTICE + displayName + "回复了问题: " + questionTitle + WEBANK_LINK_NOTICE
	}
	if sign == 3 {
		Content = HEADER_WEBANK_NOTICE + displayName + "邀请你回答问题: " + questionTitle + WEBANK_LINK_NOTICE
	}

	log.Infof(fmt.Sprintf("send mail notice Content = %s", Content))

	// body
	// 获取缓存中的agentID
	log.Debugf("Config = %s", g.Config)
	agentID, _ := strconv.Atoi(g.Config.AgentID)
	log.Infof("after agentID = %s", agentID)
	weChatNotice := WeChatNotice{
		Touser:  touser,
		Toparty: "",
		Totag:   "",
		Msgtype: "text",
		AgentID: agentID,
		Text: Text{
			Content: Content,
		},
		Safe:                   0,
		EnableIdTrans:          0,
		EnableDuplicateCheck:   0,
		DuplicateCheckInterval: 1800,
	}
	notice, err := json.Marshal(&weChatNotice)
	if err != nil {
		log.Error(err)
	}
	log.Infof("json notice = %s", notice)
	reader := bytes.NewReader(notice)
	// send
	sendURL := UrlConfig{
		AccessToken: accessToken,
		URL:         SEND_WECHAT_URL,
	}
	url := sendURL.BuildURL()
	log.Debugf("build url = %s", url)
	resp, err := client.Post(url, "application/json", reader)
	if err != nil {
		log.Errorf("err = %s", err)
	}
	if resp != nil {
		log.Infof("resp = %s", resp)
		defer resp.Body.Close()
	}
}

type WeChatNotice struct {
	Touser                 string `json:"touser"`
	Toparty                string `json:"toparty"`
	Totag                  string `json:"totag"`
	Msgtype                string `json:"msgtype"`
	AgentID                int    `json:"agentid"`
	Text                   Text   `json:"text"`
	Safe                   int    `json:"safe"`
	EnableIdTrans          int    `json:"enable_id_trans"`
	EnableDuplicateCheck   int    `json:"enable_duplicate_check"`
	DuplicateCheckInterval int    `json:"duplicate_check_interval"`
}

type Text struct {
	Content string `json:"content"`
}
