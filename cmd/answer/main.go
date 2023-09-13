package main

import (
	_ "corpwechat"
	answercmd "github.com/answerdev/answer/cmd"
)

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
func main() {
	answercmd.Main()
}
