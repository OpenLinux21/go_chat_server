package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB
var logger *log.Logger

// Config 用于读取 ./serverconfig.cfg 配置文件中的 bindport 配置
type Config struct {
	BindPort int
}

// readConfig 从指定文件读取配置（例如：bindport = 23455）
func readConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &Config{}
	buf := make([]byte, 1024)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	content := string(buf[:n])
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "bindport" {
			port, err := strconv.Atoi(value)
			if err != nil {
				return nil, err
			}
			cfg.BindPort = port
		}
	}
	return cfg, nil
}

// createDirs 自动创建所需目录
func createDirs() {
	dirs := []string{"./data", "./files", "./files/cache"}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			os.MkdirAll(dir, os.ModePerm)
			log.Println("Created directory:", dir)
		}
	}
}

// initLogger 初始化日志输出，同时将日志写入 server.log 文件
func initLogger() {
	f, err := os.OpenFile("server.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal("Failed to open log file:", err)
	}
	logger = log.New(io.MultiWriter(os.Stdout, f), "", log.LstdFlags)
}

// initDB 打开 SQLite 数据库（./data/sqlite.db），并自动迁移所需数据表
func initDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("./data/sqlite.db"), &gorm.Config{})
	if err != nil {
		logger.Fatal("Failed to connect database:", err)
	}
	// 自动创建数据表
	db.AutoMigrate(&User{}, &Session{}, &Friend{}, &FriendRequest{}, &PrivateChat{}, &GroupChat{}, &GroupMember{}, &Message{}, &FileRecord{})
	logger.Println("Database initialized")
}

// ------------------------- 数据库模型定义 -------------------------

type User struct {
	ID        uint      `gorm:"primaryKey"`
	Username  string    `gorm:"uniqueIndex"`
	Password  string    // 使用 bcrypt 加密
	Avatar    string    // 头像 URL（无头像则为空）
	Introduce string    // 自我介绍
	JoinTime  time.Time // 注册时间
	Mode      string    // 状态：online, busy, offline
}

type Session struct {
	ID     uint `gorm:"primaryKey"`
	UserID uint
	Token  string    `gorm:"uniqueIndex"` // userroot_id
	Expiry time.Time // 有效期（16天）
}

type Friend struct {
	ID       uint `gorm:"primaryKey"`
	UserID   uint
	FriendID uint
	Blocked  bool // 是否屏蔽
}

type FriendRequest struct {
	ID         uint      `gorm:"primaryKey"`
	FromUserID uint
	ToUserID   uint
	Status     string    // pending, accepted, rejected
	CreatedAt  time.Time
}

type PrivateChat struct {
	ID        uint      `gorm:"primaryKey"`
	UUID      string    `gorm:"uniqueIndex"` // 唯一标识符
	User1ID   uint
	User2ID   uint
	CreatedAt time.Time
}

type GroupChat struct {
	ID          uint      `gorm:"primaryKey"`
	UUID        string    `gorm:"uniqueIndex"`
	GroupName   string
	CreatorID   uint
	Avatar      string
	Description string
	CreatedAt   time.Time
}

type GroupMember struct {
	ID      uint `gorm:"primaryKey"`
	GroupID uint
	UserID  uint
	Role    string // member, admin, creator
}

type Message struct {
	ID          uint      `gorm:"primaryKey"`
	ChatUUID    string    // 私聊或群聊唯一标识
	SenderID    uint
	Content     string
	Timestamp   time.Time
	MessageType string // text, file
}

type FileRecord struct {
	ID        uint      `gorm:"primaryKey"`
	ChatUUID  string
	SenderID  uint
	FilePath  string    // 存储路径
	FileType  string
	Size      int64
	Sha1      string    // 新增字段：文件的 SHA1 值
	Timestamp time.Time
}

// ------------------------- 工具函数 -------------------------

// generateToken 生成指定长度的随机字符串（用于 userroot_id）
func generateToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	token := make([]byte, length)
	for i := range token {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			token[i] = charset[0]
		} else {
			token[i] = charset[n.Int64()]
		}
	}
	return string(token)
}

// hashPassword 使用 bcrypt 加密密码
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// checkPasswordHash 验证密码
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// computeSha1 从 r 中读取数据并返回其 SHA1 值
func computeSha1(r io.Reader) (string, error) {
	h := sha1.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// getUserFromToken 根据 token 获取用户（并验证有效期）
func getUserFromToken(token string) (*User, error) {
	var session Session
	result := db.Where("token = ? AND expiry > ?", token, time.Now()).First(&session)
	if result.Error != nil {
		return nil, errors.New("invalid or expired token")
	}
	var user User
	result = db.First(&user, session.UserID)
	if result.Error != nil {
		return nil, errors.New("user not found")
	}
	return &user, nil
}

// authMiddleware 用于需要认证的 API，从 HTTP Header 中读取 Authorization Bearer Token
func authMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "code": "unauthorized", "message": "Missing token"})
		c.Abort()
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	user, err := getUserFromToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "code": "unauthorized", "message": err.Error()})
		c.Abort()
		return
	}
	// 将用户信息放入上下文，方便后续处理
	c.Set("user", user)
	c.Next()
}

// CORSMiddleware 解决本地访问时可能遇到的跨域问题
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 允许所有域名访问
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		// 允许跨域请求携带 cookie 等信息
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		// 允许客户端传递的请求头
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Content-Length, X-Requested-With")
		// 允许的请求方法
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")

		// 如果是 OPTIONS 预检请求，则直接返回 204 状态码
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// startCacheCleanup 定时清理 ./files/cache 下超过 16 天的文件
func startCacheCleanup() {
	go func() {
		for {
			files, err := os.ReadDir("./files/cache")
			if err == nil {
				for _, file := range files {
					filePath := filepath.Join("./files/cache", file.Name())
					info, err := os.Stat(filePath)
					if err == nil {
						if time.Since(info.ModTime()) > 16*24*time.Hour {
							os.Remove(filePath)
							logger.Println("Removed old cache file:", filePath)
						}
					}
				}
			}
			time.Sleep(24 * time.Hour)
		}
	}()
}

// ------------------------- main 函数 -------------------------

func main() {
	cfg, err := readConfig("./serverconfig.cfg")
	if err != nil {
		log.Fatal("Error reading config:", err)
	}
	createDirs()
	initLogger()
	initDB()
	startCacheCleanup()

	router := gin.Default()
	// 使用 CORS 中间件解决跨域问题
	router.Use(CORSMiddleware())

	// API v1 分组
	v1 := router.Group("/api/v1")
	{
		users := v1.Group("/users")
		{
			users.POST("/register", userRegister)
			users.POST("/login", userLogin)
			users.GET("/profile", userGetProfile)
			users.PUT("/profile", authMiddleware, userUpdateProfile)
			users.DELETE("", authMiddleware, userDelete)
			users.PUT("/password", authMiddleware, userChangePassword)
		}
		v1.POST("/authcheck", authCheck)
		v1.POST("/token/refresh", tokenRefresh)

		// 好友模块
		v1.POST("/:username/friends", authMiddleware, addFriend)
		v1.DELETE("/:username/friends", authMiddleware, deleteFriend)
		v1.GET("/:username/friends", authMiddleware, getFriendList)
		v1.POST("/:username/friends/block", authMiddleware, blockUser)
		v1.POST("/:username/friends/request", authMiddleware, sendFriendRequest)
		v1.PUT("/:username/friends/request", authMiddleware, handleFriendRequest)
	}

	// API v2 分组（聊天相关接口）
	v2 := router.Group("/api/v2")
	{
		chats := v2.Group("/chats")
		{
			private := chats.Group("/private")
			{
				private.POST("", authMiddleware, createPrivateChat)
				private.POST("/:uuid/messages", authMiddleware, sendPrivateMessage)
					private.GET("/:uuid/messages", authMiddleware, getPrivateMessages)
						private.POST("/:uuid/files", authMiddleware, sendPrivateFile)
							private.GET("/:uuid/files", authMiddleware, getPrivateFiles)
								private.DELETE("/:uuid/messages/:messageId/revoke", authMiddleware, revokePrivateMessage)
									private.DELETE("/:uuid/messages/:messageId", authMiddleware, deletePrivateMessage)
										private.PUT("/:uuid/messages/:messageId", authMiddleware, editPrivateMessage)
											private.GET("/:uuid/history", authMiddleware, getPrivateHistory)
												private.POST("/:uuid/receipt", authMiddleware, receiptPrivateMessage)
			}
			groups := chats.Group("/groups")
			{
				groups.POST("", authMiddleware, createGroupChat)
				groups.PUT("/:uuid/name", authMiddleware, updateGroupName)
				groups.PUT("/:uuid/avatar", authMiddleware, updateGroupAvatar)
				groups.PUT("/:uuid/description", authMiddleware, updateGroupDescription)
				groups.POST("/:uuid/admin", authMiddleware, setGroupAdmin)
				groups.DELETE("/:uuid/admin", authMiddleware, revokeGroupAdmin)
				groups.GET("/:uuid/members", authMiddleware, getGroupMembers)
				groups.DELETE("/:uuid/members/self", authMiddleware, leaveGroup)
				groups.DELETE("/:uuid/members/:user_id", authMiddleware, removeGroupMember)
				groups.DELETE("/:uuid", authMiddleware, deleteGroupChat)
				groups.GET("/:uuid/invite", authMiddleware, generateGroupInvite)
				groups.POST("/:uuid/messages", authMiddleware, sendGroupMessage)
				groups.GET("/:uuid/messages", authMiddleware, getGroupMessages)
				groups.POST("/:uuid/files", authMiddleware, sendGroupFile)
				groups.GET("/:uuid/files", authMiddleware, getGroupFiles)
				groups.DELETE("/:uuid/messages/:messageId/revoke", authMiddleware, revokeGroupMessage)
				groups.DELETE("/:uuid/messages/:messageId", authMiddleware, deleteGroupMessage)
				groups.PUT("/:uuid/messages/:messageId", authMiddleware, editGroupMessage)
				groups.GET("/:uuid/history", authMiddleware, getGroupHistory)
				groups.POST("/:uuid/receipt", authMiddleware, receiptGroupMessage)
			}
		}
	}

	addr := fmt.Sprintf(":%d", cfg.BindPort)
	logger.Println("Server starting on port", cfg.BindPort)
	router.Run(addr)
}

// ------------------------- API v1 用户模块 -------------------------

// 用户注册接口：POST /api/v1/users/register
func userRegister(c *gin.Context) {
	var json struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "code": "invalid_params", "message": err.Error()})
		return
	}
	username := json.Username
	password := json.Password

	// 检查用户名：仅允许字母、数字、下划线
	validUsername := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !validUsername.MatchString(username) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "code": "err2", "message": "用户名包含非法字符"})
		return
	}
	// 检查用户名是否存在
	var count int64
	db.Model(&User{}).Where("username = ?", username).Count(&count)
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "code": "err1", "message": "用户名已存在"})
		return
	}
	// 检查密码长度
	if len(password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "code": "err3", "message": "密码太简单"})
		return
	}
	if len(password) > 128 {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "code": "err4", "message": "密码太长"})
		return
	}
	// 检查密码字符（允许大小写字母、数字及常见特殊符号）
	validPassword := regexp.MustCompile(`^[a-zA-Z0-9!@#\$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>\/?]+$`)
	if !validPassword.MatchString(password) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "code": "err5", "message": "密码包含非法字符"})
		return
	}
	hashedPassword, err := hashPassword(password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "code": "server_error", "message": err.Error()})
		return
	}
	user := User{
		Username: username,
		Password: hashedPassword,
		JoinTime: time.Now(),
		Mode:     "online",
	}
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "code": "server_error", "message": err.Error()})
		return
	}
	logger.Println("User registered:", username)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": true})
}

// 用户登录接口：POST /api/v1/users/login
func userLogin(c *gin.Context) {
	var json struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	username := json.Username
	password := json.Password

	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "用户不存在或密码错误"})
		return
	}
	if !checkPasswordHash(password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "用户不存在或密码错误"})
		return
	}
	// 生成 token（userroot_id），有效期 16 天
	token := generateToken(32)
	expiry := time.Now().Add(16 * 24 * time.Hour)
	session := Session{
		UserID: user.ID,
		Token:  token,
		Expiry: expiry,
	}
	if err := db.Create(&session).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}
	logger.Println("User logged in:", username)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": gin.H{"userroot_id": token}})
}

// 获取用户信息接口：GET /api/v1/users/profile
func userGetProfile(c *gin.Context) {
	username := c.Query("username")
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "缺少参数 username"})
		return
	}
	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "用户不存在"})
		return
	}
	// 判断请求方是否为本人（携带有效 token 时返回更多信息）
	moreInfo := false
	token := c.GetHeader("Authorization")
	if token != "" && strings.HasPrefix(token, "Bearer ") {
		t := strings.TrimPrefix(token, "Bearer ")
		u, err := getUserFromToken(t)
		if err == nil && u.Username == username {
			moreInfo = true
		}
	}
	profile := gin.H{
		"username":       user.Username,
		"user_id":        user.ID,
		"user_avatar":    func() interface{} { if user.Avatar == "" { return 0 } else { return user.Avatar } }(),
		"user_introduce": user.Introduce,
		"join_time":      user.JoinTime.Format("2006-01-02"),
		"mode":           user.Mode,
	}
	// 如果是本人，返回额外信息
	if moreInfo {
		profile["extra_info"] = "这里可以返回更多个人信息"
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": profile})
}

// 更新用户信息接口：PUT /api/v1/users/profile
func userUpdateProfile(c *gin.Context) {
	userInterface, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "未认证"})
		return
	}
	currentUser := userInterface.(*User)

	var json map[string]interface{}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	// 禁止修改不可变字段
	if _, ok := json["user_id"]; ok {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "不可修改字段 user_id"})
		return
	}
	if _, ok := json["userroot_id"]; ok {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "不可修改字段 userroot_id"})
		return
	}
	// 允许修改 username、user_avatar、user_introduce、mode
	if newUsername, ok := json["username"].(string); ok {
		validUsername := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
		if !validUsername.MatchString(newUsername) {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "用户名包含非法字符"})
			return
		}
		currentUser.Username = newUsername
	}
	if avatar, ok := json["user_avatar"].(string); ok {
		currentUser.Avatar = avatar
	}
	if intro, ok := json["user_introduce"].(string); ok {
		currentUser.Introduce = intro
	}
	if mode, ok := json["mode"].(string); ok {
		if mode != "online" && mode != "busy" && mode != "offline" {
			c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "无效的状态"})
			return
		}
		currentUser.Mode = mode
	}
	if err := db.Save(currentUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}
	logger.Println("User updated profile:", currentUser.Username)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 删除用户接口：DELETE /api/v1/users
func userDelete(c *gin.Context) {
	userInterface, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "未认证"})
		return
	}
	currentUser := userInterface.(*User)
	var json struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	if json.Username != currentUser.Username || !checkPasswordHash(json.Password, currentUser.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "认证失败"})
		return
	}
	// 此处简化处理：直接删除用户（实际可改为标记删除，7天后彻底清除数据）
	if err := db.Delete(&User{}, currentUser.ID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}
	logger.Println("User deletion requested:", currentUser.Username)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": true})
}

// 验证认证状态接口：POST /api/v1/authcheck
func authCheck(c *gin.Context) {
	var json struct {
		Username   string `json:"username"`
		UserRootID string `json:"userroot_id"`
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	var user User
	if err := db.Where("username = ?", json.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "用户不存在"})
		return
	}
	var session Session
	if err := db.Where("token = ? AND user_id = ? AND expiry > ?", json.UserRootID, user.ID, time.Now()).First(&session).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "认证失败"})
		return
	}
	remaining := int(session.Expiry.Sub(time.Now()).Seconds())
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": gin.H{"valid": true, "remaining": remaining}})
}

// 修改密码接口：PUT /api/v1/users/password
func userChangePassword(c *gin.Context) {
	userInterface, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "未认证"})
		return
	}
	currentUser := userInterface.(*User)
	var json struct {
		Username    string `json:"username"`
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	if json.Username != currentUser.Username {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "认证失败"})
		return
	}
	if !checkPasswordHash(json.OldPassword, currentUser.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "旧密码错误"})
		return
	}
	if len(json.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "code": "err3", "message": "密码太简单"})
		return
	}
	if len(json.NewPassword) > 128 {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "code": "err4", "message": "密码太长"})
		return
	}
	validPassword := regexp.MustCompile(`^[a-zA-Z0-9!@#\$%\^&\*\(\)_\+\-=\[\]{};':"\\|,.<>\/?]+$`)
	if !validPassword.MatchString(json.NewPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "code": "err5", "message": "密码包含非法字符"})
		return
	}
	hashedPassword, err := hashPassword(json.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}
	currentUser.Password = hashedPassword
	if err := db.Save(currentUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}
	logger.Println("User changed password:", currentUser.Username)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": true})
}

// Token 刷新接口：POST /api/v1/token/refresh
func tokenRefresh(c *gin.Context) {
	var json struct {
		Username   string `json:"username"`
		UserRootID string `json:"userroot_id"`
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	var user User
	if err := db.Where("username = ?", json.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "用户不存在"})
		return
	}
	var session Session
	if err := db.Where("token = ? AND user_id = ? AND expiry > ?", json.UserRootID, user.ID, time.Now()).First(&session).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "认证失败"})
		return
	}
	newToken := generateToken(32)
	session.Token = newToken
	session.Expiry = time.Now().Add(16 * 24 * time.Hour)
	if err := db.Save(&session).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}
	logger.Println("Token refreshed for user:", user.Username)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": gin.H{"userroot_id": newToken, "expiry": session.Expiry.Unix()}})
}

// ------------------------- API v1 好友模块 -------------------------

// 添加好友接口：POST /api/v1/{username}/friends
func addFriend(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	targetFriendIDStr := c.PostForm("target_user_id")
	targetFriendID, err := strconv.ParseUint(targetFriendIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "无效的 target_user_id"})
		return
	}
	var friend Friend
	if err := db.Where("user_id = ? AND friend_id = ?", currentUser.ID, targetFriendID).First(&friend).Error; err == nil {
		c.JSON(http.StatusOK, gin.H{"status": "success", "data": 3})
		return
	}
	newFriend1 := Friend{
		UserID:   currentUser.ID,
		FriendID: uint(targetFriendID),
	}
	newFriend2 := Friend{
		UserID:   uint(targetFriendID),
		FriendID: currentUser.ID,
	}
	if err := db.Create(&newFriend1).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "添加好友失败"})
		return
	}
	db.Create(&newFriend2)
	logger.Println("Friend added:", currentUser.ID, "->", targetFriendID)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": 1})
}

// 删除好友接口：DELETE /api/v1/{username}/friends
func deleteFriend(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	targetFriendIDStr := c.PostForm("target_user_id")
	targetFriendID, err := strconv.ParseUint(targetFriendIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "无效的 target_user_id"})
		return
	}
	if err := db.Where("user_id = ? AND friend_id = ?", currentUser.ID, targetFriendID).Delete(&Friend{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "data": 2})
		return
	}
	db.Where("user_id = ? AND friend_id = ?", targetFriendID, currentUser.ID).Delete(&Friend{})
	logger.Println("Friend deleted:", currentUser.ID, "->", targetFriendID)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": 1})
}

// 获取好友列表接口：GET /api/v1/{username}/friends
func getFriendList(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	var friends []Friend
	if err := db.Where("user_id = ?", currentUser.ID).Find(&friends).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}
	var friendList []gin.H
	for _, f := range friends {
		var user User
		if err := db.First(&user, f.FriendID).Error; err == nil {
			friendList = append(friendList, gin.H{"user_id": user.ID, "username": user.Username})
		}
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": friendList})
}

// 屏蔽用户接口：POST /api/v1/{username}/friends/block
func blockUser(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	targetFriendIDStr := c.PostForm("target_user_id")
	targetFriendID, err := strconv.ParseUint(targetFriendIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "无效的 target_user_id"})
		return
	}
	if uint(targetFriendID) == currentUser.ID {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "data": 2, "message": "不能屏蔽自己"})
		return
	}
	db.Where("user_id = ? AND friend_id = ?", currentUser.ID, targetFriendID).Delete(&Friend{})
	blockEntry := Friend{
		UserID:   currentUser.ID,
		FriendID: uint(targetFriendID),
		Blocked:  true,
	}
	if err := db.Create(&blockEntry).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "data": 2, "message": "操作失败"})
		return
	}
	logger.Println("User blocked:", currentUser.ID, "blocked", targetFriendID)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": 1})
}

// 发送好友请求接口：POST /api/v1/{username}/friends/request
func sendFriendRequest(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	targetUserIDStr := c.PostForm("target_user_id")
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "无效的 target_user_id"})
		return
	}
	friendRequest := FriendRequest{
		FromUserID: currentUser.ID,
		ToUserID:   uint(targetUserID),
		Status:     "pending",
		CreatedAt:  time.Now(),
	}
	if err := db.Create(&friendRequest).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "请求发送失败"})
		return
	}
	logger.Println("Friend request sent:", currentUser.ID, "to", targetUserID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 处理好友请求接口：PUT /api/v1/{username}/friends/request
func handleFriendRequest(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	var json struct {
		RequestID uint   `json:"request_id"`
		Action    string `json:"action"` // accept 或 reject
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	var req FriendRequest
	if err := db.First(&req, json.RequestID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "请求不存在"})
		return
	}
	if req.ToUserID != currentUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "没有权限处理该请求"})
		return
	}
	if json.Action == "accept" {
		req.Status = "accepted"
		friend1 := Friend{
			UserID:   req.FromUserID,
			FriendID: req.ToUserID,
		}
		friend2 := Friend{
			UserID:   req.ToUserID,
			FriendID: req.FromUserID,
		}
		db.Create(&friend1)
		db.Create(&friend2)
	} else if json.Action == "reject" {
		req.Status = "rejected"
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "无效的操作"})
		return
	}
	db.Save(&req)
	logger.Println("Friend request handled:", json.RequestID, "action:", json.Action)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// ------------------------- API v2 私聊模块 -------------------------

// 创建私聊会话接口：POST /api/v2/chats/private
func createPrivateChat(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	targetUserIDStr := c.PostForm("target_user_id")
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "无效的 target_user_id"})
		return
	}
	newUUID := uuid.New().String()
	chat := PrivateChat{
		UUID:      newUUID,
		User1ID:   currentUser.ID,
		User2ID:   uint(targetUserID),
		CreatedAt: time.Now(),
	}
	if err := db.Create(&chat).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "创建聊天会话失败"})
		return
	}
	logger.Println("Private chat created:", newUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": newUUID})
}

// 发送文字消息接口：POST /api/v2/chats/private/{uuid}/messages
func sendPrivateMessage(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	chatUUID := c.Param("uuid")
	var json struct {
		Message   string `json:"message"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	msg := Message{
		ChatUUID:    chatUUID,
		SenderID:    currentUser.ID,
		Content:     json.Message,
		Timestamp:   time.Now(),
		MessageType: "text",
	}
	if err := db.Create(&msg).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "发送消息失败"})
		return
	}
	logger.Println("Private message sent in chat", chatUUID, "by", currentUser.ID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 获取消息记录接口：GET /api/v2/chats/private/{uuid}/messages
func getPrivateMessages(c *gin.Context) {
	chatUUID := c.Param("uuid")
	var messages []Message
	if err := db.Where("chat_uuid = ?", chatUUID).Order("timestamp asc").Find(&messages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "获取消息记录失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": messages})
}

// 发送文件接口：POST /api/v2/chats/private/{uuid}/files
func sendPrivateFile(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	chatUUID := c.Param("uuid")
	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "文件上传失败"})
		return
	}
	if fileHeader.Size > 128*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "文件大小超过限制"})
		return
	}
	// 打开文件并计算 SHA1 值
	file, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "打开文件失败"})
		return
	}
	defer file.Close()
	sha1sum, err := computeSha1(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "计算 SHA1 失败"})
		return
	}
	// 检查是否已有相同文件
	var existing FileRecord
	if err := db.Where("sha1 = ?", sha1sum).First(&existing).Error; err == nil {
		logger.Println("重复文件，直接复用：", existing.FilePath)
		c.JSON(http.StatusOK, gin.H{"status": "success", "data": existing.FilePath})
		return
	}
	// 重新定位文件指针
	if seeker, ok := file.(io.Seeker); ok {
		seeker.Seek(0, 0)
	}
	savePath := filepath.Join("./files/cache", fileHeader.Filename)
	if err := c.SaveUploadedFile(fileHeader, savePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "保存文件失败"})
		return
	}
	fileRecord := FileRecord{
		ChatUUID:  chatUUID,
		SenderID:  currentUser.ID,
		FilePath:  savePath,
		FileType:  fileHeader.Header.Get("Content-Type"),
		Size:      fileHeader.Size,
		Sha1:      sha1sum,
		Timestamp: time.Now(),
	}
	db.Create(&fileRecord)
	logger.Println("Private file sent in chat", chatUUID, "by", currentUser.ID)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": savePath})
}

// 获取文件接口：GET /api/v2/chats/private/{uuid}/files
func getPrivateFiles(c *gin.Context) {
	chatUUID := c.Param("uuid")
	var files []FileRecord
	if err := db.Where("chat_uuid = ?", chatUUID).Order("timestamp asc").Find(&files).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "获取文件记录失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": files})
}

// 撤回消息接口：DELETE /api/v2/chats/private/{uuid}/messages/{messageId}/revoke
func revokePrivateMessage(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	chatUUID := c.Param("uuid")
	messageId := c.Param("messageId")
	var msg Message
	if err := db.Where("id = ? AND chat_uuid = ?", messageId, chatUUID).First(&msg).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "消息不存在"})
		return
	}
	if msg.SenderID != currentUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "没有权限撤回消息"})
		return
	}
	db.Delete(&msg)
	logger.Println("Private message revoked:", messageId)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 删除消息接口：DELETE /api/v2/chats/private/{uuid}/messages/{messageId}
func deletePrivateMessage(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	chatUUID := c.Param("uuid")
	messageId := c.Param("messageId")
	var msg Message
	if err := db.Where("id = ? AND chat_uuid = ?", messageId, chatUUID).First(&msg).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "消息不存在"})
		return
	}
	if msg.SenderID != currentUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "没有权限删除消息"})
		return
	}
	db.Delete(&msg)
	logger.Println("Private message deleted locally:", messageId)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 编辑已发送消息接口：PUT /api/v2/chats/private/{uuid}/messages/{messageId}
func editPrivateMessage(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	chatUUID := c.Param("uuid")
	messageId := c.Param("messageId")
	var json struct {
		NewMessage string `json:"new_message"`
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	var msg Message
	if err := db.Where("id = ? AND chat_uuid = ?", messageId, chatUUID).First(&msg).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "消息不存在"})
		return
	}
	if msg.SenderID != currentUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "没有权限编辑消息"})
		return
	}
	msg.Content = json.NewMessage
	db.Save(&msg)
	logger.Println("Private message edited:", messageId)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 获取历史消息接口：GET /api/v2/chats/private/{uuid}/history
func getPrivateHistory(c *gin.Context) {
	chatUUID := c.Param("uuid")
	limitStr := c.Query("limit")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 50
	}
	var messages []Message
	if err := db.Where("chat_uuid = ?", chatUUID).Order("timestamp desc").Limit(limit).Find(&messages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "获取历史消息失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": messages})
}

// 消息状态回执接口：POST /api/v2/chats/private/{uuid}/receipt
func receiptPrivateMessage(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	chatUUID := c.Param("uuid")
	var json struct {
		MessageID string `json:"messageId"`
		Status    string `json:"status"` // delivered 或 read
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	logger.Println("Private message receipt:", json.MessageID, "status:", json.Status, "by user", currentUser.ID, "in chat", chatUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// ------------------------- API v2 群聊模块 -------------------------

// 创建群聊接口：POST /api/v2/chats/groups
func createGroupChat(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	groupName := c.PostForm("groupName")
	members := c.PostForm("members") // 简单处理：用逗号分隔的用户 ID
	newUUID := uuid.New().String()
	group := GroupChat{
		UUID:      newUUID,
		GroupName: groupName,
		CreatorID: currentUser.ID,
		CreatedAt: time.Now(),
	}
	if err := db.Create(&group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "创建群聊失败"})
		return
	}
	// 添加创建者到群成员中（角色 creator）
	db.Create(&GroupMember{
		GroupID: group.ID,
	   UserID:  currentUser.ID,
	   Role:    "creator",
	})
	// 添加初始成员（角色 member）
	if members != "" {
		memberIDs := strings.Split(members, ",")
		for _, mid := range memberIDs {
			uid, err := strconv.ParseUint(strings.TrimSpace(mid), 10, 64)
			if err == nil {
				db.Create(&GroupMember{
					GroupID: group.ID,
	      UserID:  uint(uid),
					  Role:    "member",
				})
			}
		}
	}
	logger.Println("Group chat created:", newUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": newUUID})
}

// 修改群名称接口：PUT /api/v2/chats/groups/{uuid}/name
func updateGroupName(c *gin.Context) {
	userInterface, _ := c.Get("user")
	_ = userInterface.(*User)
	groupUUID := c.Param("uuid")
	newGroupName := c.PostForm("new_groupName")
	var group GroupChat
	if err := db.Where("uuid = ?", groupUUID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "群聊不存在"})
		return
	}
	group.GroupName = newGroupName
	db.Save(&group)
	logger.Println("Group chat name updated:", groupUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 修改群头像接口：PUT /api/v2/chats/groups/{uuid}/avatar
func updateGroupAvatar(c *gin.Context) {
	userInterface, _ := c.Get("user")
	_ = userInterface.(*User)
	groupUUID := c.Param("uuid")
	newAvatar := c.PostForm("new_avatar")
	var group GroupChat
	if err := db.Where("uuid = ?", groupUUID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "群聊不存在"})
		return
	}
	group.Avatar = newAvatar
	db.Save(&group)
	logger.Println("Group chat avatar updated:", groupUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 修改群介绍接口：PUT /api/v2/chats/groups/{uuid}/description
func updateGroupDescription(c *gin.Context) {
	userInterface, _ := c.Get("user")
	_ = userInterface.(*User)
	groupUUID := c.Param("uuid")
	newDescription := c.PostForm("new_description")
	var group GroupChat
	if err := db.Where("uuid = ?", groupUUID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "群聊不存在"})
		return
	}
	group.Description = newDescription
	db.Save(&group)
	logger.Println("Group chat description updated:", groupUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 设置管理员接口：POST /api/v2/chats/groups/{uuid}/admin
func setGroupAdmin(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	groupUUID := c.Param("uuid")
	targetUserIDStr := c.PostForm("target_user_id")
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "无效的 target_user_id"})
		return
	}
	var group GroupChat
	if err := db.Where("uuid = ?", groupUUID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "群聊不存在"})
		return
	}
	// 仅群创建者有权限
	if group.CreatorID != currentUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "没有权限设置管理员"})
		return
	}
	var member GroupMember
	if err := db.Where("group_id = ? AND user_id = ?", group.ID, uint(targetUserID)).First(&member).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "用户不在群聊中"})
		return
	}
	member.Role = "admin"
	db.Save(&member)
	logger.Println("Group admin set:", targetUserID, "in group", groupUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 撤销管理员接口：DELETE /api/v2/chats/groups/{uuid}/admin
func revokeGroupAdmin(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	groupUUID := c.Param("uuid")
	targetUserIDStr := c.PostForm("target_user_id")
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "无效的 target_user_id"})
		return
	}
	var group GroupChat
	if err := db.Where("uuid = ?", groupUUID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "群聊不存在"})
		return
	}
	if group.CreatorID != currentUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "没有权限撤销管理员"})
		return
	}
	var member GroupMember
	if err := db.Where("group_id = ? AND user_id = ?", group.ID, uint(targetUserID)).First(&member).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "用户不在群聊中"})
		return
	}
	member.Role = "member"
	db.Save(&member)
	logger.Println("Group admin revoked:", targetUserID, "in group", groupUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 获取群成员列表接口：GET /api/v2/chats/groups/{uuid}/members
func getGroupMembers(c *gin.Context) {
	groupUUID := c.Param("uuid")
	var group GroupChat
	if err := db.Where("uuid = ?", groupUUID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "群聊不存在"})
		return
	}
	var members []GroupMember
	if err := db.Where("group_id = ?", group.ID).Find(&members).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "获取群成员失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": members})
}

// 退出群聊接口：DELETE /api/v2/chats/groups/{uuid}/members/self
func leaveGroup(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	groupUUID := c.Param("uuid")
	var group GroupChat
	if err := db.Where("uuid = ?", groupUUID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "群聊不存在"})
		return
	}
	db.Where("group_id = ? AND user_id = ?", group.ID, currentUser.ID).Delete(&GroupMember{})
	logger.Println("User left group:", currentUser.ID, "from group", groupUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 移除群成员接口（管理员操作）：DELETE /api/v2/chats/groups/{uuid}/members/{user_id}
func removeGroupMember(c *gin.Context) {
	userInterface, _ := c.Get("user")
	_ = userInterface.(*User)
	groupUUID := c.Param("uuid")
	targetUserIDStr := c.Param("user_id")
	targetUserID, err := strconv.ParseUint(targetUserIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "无效的 user_id"})
		return
	}
	var group GroupChat
	if err := db.Where("uuid = ?", groupUUID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "群聊不存在"})
		return
	}
	db.Where("group_id = ? AND user_id = ?", group.ID, uint(targetUserID)).Delete(&GroupMember{})
	logger.Println("Group member removed:", targetUserID, "from group", groupUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 删除群聊接口：DELETE /api/v2/chats/groups/{uuid}
func deleteGroupChat(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	groupUUID := c.Param("uuid")
	var group GroupChat
	if err := db.Where("uuid = ?", groupUUID).First(&group).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "群聊不存在"})
		return
	}
	if group.CreatorID != currentUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "只有群聊创建者有权限删除群聊"})
		return
	}
	db.Delete(&group)
	logger.Println("Group chat deleted:", groupUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 生成群聊邀请链接接口：GET /api/v2/chats/groups/{uuid}/invite
func generateGroupInvite(c *gin.Context) {
	groupUUID := c.Param("uuid")
	inviteLink := fmt.Sprintf("http://yourdomain.com/invite/%s", groupUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": inviteLink})
}

// 群聊发送文字消息接口：POST /api/v2/chats/groups/{uuid}/messages
func sendGroupMessage(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	groupUUID := c.Param("uuid")
	var json struct {
		Message   string `json:"message"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	msg := Message{
		ChatUUID:    groupUUID,
		SenderID:    currentUser.ID,
		Content:     json.Message,
		Timestamp:   time.Now(),
		MessageType: "text",
	}
	db.Create(&msg)
	logger.Println("Group message sent in group", groupUUID, "by", currentUser.ID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 群聊获取消息记录接口：GET /api/v2/chats/groups/{uuid}/messages
func getGroupMessages(c *gin.Context) {
	groupUUID := c.Param("uuid")
	var messages []Message
	if err := db.Where("chat_uuid = ?", groupUUID).Order("timestamp asc").Find(&messages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "获取消息记录失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": messages})
}

// 群聊发送文件接口：POST /api/v2/chats/groups/{uuid}/files
func sendGroupFile(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	groupUUID := c.Param("uuid")
	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "文件上传失败"})
		return
	}
	if fileHeader.Size > 128*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "文件大小超过限制"})
		return
	}
	// 打开文件并计算 SHA1 值
	file, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "打开文件失败"})
		return
	}
	defer file.Close()
	sha1sum, err := computeSha1(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "计算 SHA1 失败"})
		return
	}
	// 检查是否已有相同文件
	var existing FileRecord
	if err := db.Where("sha1 = ?", sha1sum).First(&existing).Error; err == nil {
		logger.Println("重复文件，直接复用：", existing.FilePath)
		c.JSON(http.StatusOK, gin.H{"status": "success", "data": existing.FilePath})
		return
	}
	// 重新定位文件指针
	if seeker, ok := file.(io.Seeker); ok {
		seeker.Seek(0, 0)
	}
	savePath := filepath.Join("./files/cache", fileHeader.Filename)
	if err := c.SaveUploadedFile(fileHeader, savePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "保存文件失败"})
		return
	}
	fileRecord := FileRecord{
		ChatUUID:  groupUUID,
		SenderID:  currentUser.ID,
		FilePath:  savePath,
		FileType:  fileHeader.Header.Get("Content-Type"),
		Size:      fileHeader.Size,
		Sha1:      sha1sum,
		Timestamp: time.Now(),
	}
	db.Create(&fileRecord)
	logger.Println("Group file sent in group", groupUUID, "by", currentUser.ID)
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": savePath})
}

// 群聊获取文件接口：GET /api/v2/chats/groups/{uuid}/files
func getGroupFiles(c *gin.Context) {
	groupUUID := c.Param("uuid")
	var files []FileRecord
	if err := db.Where("chat_uuid = ?", groupUUID).Order("timestamp asc").Find(&files).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "获取文件记录失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": files})
}

// 群聊撤回消息接口：DELETE /api/v2/chats/groups/{uuid}/messages/{messageId}/revoke
func revokeGroupMessage(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	groupUUID := c.Param("uuid")
	messageId := c.Param("messageId")
	var msg Message
	if err := db.Where("id = ? AND chat_uuid = ?", messageId, groupUUID).First(&msg).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "消息不存在"})
		return
	}
	if msg.SenderID != currentUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "没有权限撤回消息"})
		return
	}
	db.Delete(&msg)
	logger.Println("Group message revoked:", messageId)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 群聊删除消息接口：DELETE /api/v2/chats/groups/{uuid}/messages/{messageId}
func deleteGroupMessage(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	groupUUID := c.Param("uuid")
	messageId := c.Param("messageId")
	var msg Message
	if err := db.Where("id = ? AND chat_uuid = ?", messageId, groupUUID).First(&msg).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "消息不存在"})
		return
	}
	if msg.SenderID != currentUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "没有权限删除消息"})
		return
	}
	db.Delete(&msg)
	logger.Println("Group message deleted:", messageId)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 群聊编辑消息接口：PUT /api/v2/chats/groups/{uuid}/messages/{messageId}
func editGroupMessage(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	groupUUID := c.Param("uuid")
	messageId := c.Param("messageId")
	var json struct {
		NewMessage string `json:"new_message"`
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	var msg Message
	if err := db.Where("id = ? AND chat_uuid = ?", messageId, groupUUID).First(&msg).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "消息不存在"})
		return
	}
	if msg.SenderID != currentUser.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "没有权限编辑消息"})
		return
	}
	msg.Content = json.NewMessage
	db.Save(&msg)
	logger.Println("Group message edited:", messageId)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

// 获取群聊历史消息接口：GET /api/v2/chats/groups/{uuid}/history
func getGroupHistory(c *gin.Context) {
	groupUUID := c.Param("uuid")
	limitStr := c.Query("limit")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 50
	}
	var messages []Message
	if err := db.Where("chat_uuid = ?", groupUUID).Order("timestamp desc").Limit(limit).Find(&messages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "获取历史消息失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "data": messages})
}

// 群聊消息状态回执接口：POST /api/v2/chats/groups/{uuid}/receipt
func receiptGroupMessage(c *gin.Context) {
	userInterface, _ := c.Get("user")
	currentUser := userInterface.(*User)
	groupUUID := c.Param("uuid")
	var json struct {
		MessageID string `json:"messageId"`
		Status    string `json:"status"`
	}
	if err := c.ShouldBindJSON(&json); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": err.Error()})
		return
	}
	logger.Println("Group message receipt:", json.MessageID, "status:", json.Status, "by user", currentUser.ID, "in group", groupUUID)
	c.JSON(http.StatusOK, gin.H{"status": "success"})
}
