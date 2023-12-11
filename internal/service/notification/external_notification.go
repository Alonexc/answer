package notification

import (
	"context"
	"corpwechat"
	"fmt"
	"github.com/answerdev/answer/internal/base/data"
	"github.com/answerdev/answer/internal/schema"
	"github.com/answerdev/answer/internal/service/activity_common"
	"github.com/answerdev/answer/internal/service/export"
	"github.com/answerdev/answer/internal/service/notice_queue"
	usercommon "github.com/answerdev/answer/internal/service/user_common"
	"github.com/answerdev/answer/internal/service/user_notification_config"
	"github.com/segmentfault/pacman/log"
	"strings"
)

type ExternalNotificationService struct {
	data                       *data.Data
	userNotificationConfigRepo user_notification_config.UserNotificationConfigRepo
	followRepo                 activity_common.FollowRepo
	emailService               *export.EmailService
	userRepo                   usercommon.UserRepo
	notificationQueueService   notice_queue.ExternalNotificationQueueService
}

func NewExternalNotificationService(
	data *data.Data,
	userNotificationConfigRepo user_notification_config.UserNotificationConfigRepo,
	followRepo activity_common.FollowRepo,
	emailService *export.EmailService,
	userRepo usercommon.UserRepo,
	notificationQueueService notice_queue.ExternalNotificationQueueService,
) *ExternalNotificationService {
	n := &ExternalNotificationService{
		data:                       data,
		userNotificationConfigRepo: userNotificationConfigRepo,
		followRepo:                 followRepo,
		emailService:               emailService,
		userRepo:                   userRepo,
		notificationQueueService:   notificationQueueService,
	}
	notificationQueueService.RegisterHandler(n.Handler)
	return n
}

func (ns *ExternalNotificationService) Handler(ctx context.Context, msg *schema.ExternalNotificationMsg) error {
	log.Debugf("try to send external notification %+v", msg)

	//if msg.NewQuestionTemplateRawData != nil {
	//	return ns.handleNewQuestionNotification(ctx, msg)
	//}
	//if msg.NewCommentTemplateRawData != nil {
	//	return ns.handleNewCommentNotification(ctx, msg)
	//}
	//if msg.NewAnswerTemplateRawData != nil {
	//	return ns.handleNewAnswerNotification(ctx, msg)
	//}
	//if msg.NewInviteAnswerTemplateRawData != nil {
	//	return ns.handleInviteAnswerNotification(ctx, msg)
	//}

	err := ns.HandlerMessageWeChat(ctx, msg)
	if err == nil {
		return nil
	}
	log.Errorf("unknown notification message: %+v", msg)
	return nil
}

func (ns *ExternalNotificationService) HandlerMessageWeChat(ctx context.Context, msg *schema.ExternalNotificationMsg) error {
	if msg.NewQuestionTemplateRawData != nil {
		// 获取标签下所有的用户ID
		subscribers := ns.allTagsFollowers(ctx, msg)
		log.Infof("all user ids under the tag: ", subscribers)
		if subscribers == nil {
			log.Errorf("subscribers is nil")
		}
		// 去掉发布问题的作者ID
		var UserIDS []string
		for _, ID := range subscribers {
			if ID != msg.NewQuestionTemplateRawData.QuestionAuthorUserID {
				UserIDS = append(UserIDS, ID)
			}
		}
		log.Infof("removed QuestionAuthorUserID: %s", UserIDS)
		// 获取所有除去作者的标签followers用户信息
		users, _ := ns.userRepo.GetByUserIDS(ctx, UserIDS)
		log.Infof("get all user info under the tag: %s", users)
		var name = ""
		for _, user := range users {
			// 通过email截取用户名
			userName := splitName(user.EMail)
			if name == "" {
				name = userName
				continue
			}
			// 拼接用户名形式为[A｜B｜C]
			name = strings.Join([]string{name, userName}, "|")
		}
		questionTitle := msg.NewQuestionTemplateRawData.QuestionTitle
		log.Infof(fmt.Sprintf("NewQuestionTemplate: name=%s, questionTitle=%s",
			name, questionTitle))
		corpwechat.GetConnector().MailNotice(ctx, name, "", questionTitle, 0)
		return nil
	}
	if msg.NewCommentTemplateRawData != nil {
		name := splitName(msg.ReceiverEmail)
		displayName := msg.NewCommentTemplateRawData.CommentUserDisplayName
		questionTitle := msg.NewCommentTemplateRawData.QuestionTitle
		//summary := msg.NewCommentTemplateRawData.CommentSummary
		log.Infof(fmt.Sprintf("NewCommentTemplate: name=%s, displayName=%s, questionTitle=%s",
			name, displayName, questionTitle))
		corpwechat.GetConnector().MailNotice(ctx, name, displayName, questionTitle, 1)
		return nil
	}
	if msg.NewAnswerTemplateRawData != nil {
		name := splitName(msg.ReceiverEmail)
		displayName := msg.NewAnswerTemplateRawData.AnswerUserDisplayName
		questionTitle := msg.NewAnswerTemplateRawData.QuestionTitle
		//summary := msg.NewAnswerTemplateRawData.AnswerSummary
		log.Infof(fmt.Sprintf("NewAnswerTemplate name=%s, displayName=%s, questionTitle=%s", name, displayName, questionTitle))
		corpwechat.GetConnector().MailNotice(ctx, name, displayName, questionTitle, 2)
		return nil
	}

	if msg.NewInviteAnswerTemplateRawData != nil {
		name := splitName(msg.ReceiverEmail)
		displayName := msg.NewInviteAnswerTemplateRawData.InviterDisplayName
		questionTitle := msg.NewInviteAnswerTemplateRawData.QuestionTitle
		log.Infof(fmt.Sprintf("NewInviteAnswerTemplate name=%s, displayName=%s, questionTitle=%s", name, displayName, questionTitle))
		corpwechat.GetConnector().MailNotice(ctx, name, displayName, questionTitle, 3)
		return nil
	}
	return nil
}

// splitName 用于从email中截取用户名
func splitName(email string) string {
	arr := []rune(email)
	for i := 0; i < len(email); i++ {
		if arr[i] == '@' {
			name := email[0:i]
			return name
		}
	}
	return ""
}

// allTagsFollowers 获取标签下所有的用户ID
func (ns *ExternalNotificationService) allTagsFollowers(ctx context.Context, msg *schema.ExternalNotificationMsg) []string {
	tagsFollowerIDs := make([]string, 0)
	followerMapping := make(map[string]bool)
	for _, tagID := range msg.NewQuestionTemplateRawData.TagIDs {
		userIDs, err := ns.followRepo.GetFollowUserIDs(ctx, tagID)
		if err != nil {
			log.Error(err)
			continue
		}
		for _, userID := range userIDs {
			if _, ok := followerMapping[userID]; ok {
				continue
			}
			followerMapping[userID] = true
			tagsFollowerIDs = append(tagsFollowerIDs, userID)
		}
	}
	return tagsFollowerIDs
}
