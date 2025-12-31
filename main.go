package main

import (
	"database/sql"
	"embed"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*
var f embed.FS

var db *sql.DB
var jwtSecret = []byte("YOUR_SUPER_SECRET_KEY") // 生产环境请从环境变量读取

// User 模型
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"` // omitempty 防止密码哈希泄露给前端
}

func main() {
	// 1. 初始化数据库
	var err error
	db, err = sql.Open("sqlite3", "./app.db?cache=shared&mode=rwc&_journal_mode=WAL")
	if err != nil {
		log.Fatal("无法连接数据库:", err)
	}
	defer db.Close()
	initSchema()

	// 2. 初始化 Gin
	r := gin.Default()
	tmpl := template.Must(template.New("").ParseFS(f, "templates/*.html"))
	r.SetHTMLTemplate(tmpl)

	// 3. 页面路由
	r.GET("/", func(c *gin.Context) {
		// 尝试从 Cookie 获取用户信息渲染页面（可选，这里还是由前端 fetch 获取状态）
		c.HTML(http.StatusOK, "index.html", gin.H{"AppTitle": "Go Lite Auth"})
	})

	r.GET("/users", func(c *gin.Context) {
		c.HTML(http.StatusOK, "users.html", gin.H{"AppTitle": "User Management"})
	})

	// 4. API 路由
	api := r.Group("/api")
	{
		api.POST("/register", registerHandler)
		api.POST("/login", loginHandler)
		api.POST("/logout", logoutHandler)

		// 受保护的路由
		authorized := api.Group("/")
		authorized.Use(authMiddleware())
		{
			authorized.GET("/me", meHandler)
			authorized.GET("/users", listUsersHandler)
			authorized.DELETE("/users/:id", deleteUserHandler)
			authorized.PUT("/users/:id", updateUserHandler)
		}
	}

	r.Run(":8080")
}

// 初始化表结构
func initSchema() {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	db.Exec(query)
}

// --- Handlers ---

func registerHandler(c *gin.Context) {
	var u User
	if err := c.BindJSON(&u); err != nil {
		c.JSON(400, gin.H{"error": "无效的请求数据"})
		return
	}
	// 密码加密
	hash, _ := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	
	_, err := db.Exec("INSERT INTO users(username, password) VALUES(?, ?)", u.Username, string(hash))
	if err != nil {
		c.JSON(409, gin.H{"error": "用户名已存在"})
		return
	}
	c.JSON(200, gin.H{"message": "注册成功，请登录"})
}

func loginHandler(c *gin.Context) {
	var form User
	if err := c.BindJSON(&form); err != nil {
		c.JSON(400, gin.H{"error": "无效的请求"})
		return
	}

	var storedUser User
	err := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", form.Username).Scan(&storedUser.ID, &storedUser.Username, &storedUser.Password)
	
	// 验证密码
	if err != nil || bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(form.Password)) != nil {
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 生成 JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": storedUser.ID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // 24小时过期
	})
	tokenString, _ := token.SignedString(jwtSecret)

	// 设置 HttpOnly Cookie (关键安全步骤)
	// 参数: name, value, maxAge, path, domain, secure, httpOnly
	c.SetCookie("token", tokenString, 3600*24, "/", "", false, true)

	c.JSON(200, gin.H{"message": "登录成功", "user": map[string]interface{}{"id": storedUser.ID, "username": storedUser.Username}})
}

func logoutHandler(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "", false, true)
	c.JSON(200, gin.H{"message": "已退出登录"})
}

func meHandler(c *gin.Context) {
	// 从中间件获取的用户ID
	userID, _ := c.Get("user_id")
	
	var u User
	err := db.QueryRow("SELECT id, username FROM users WHERE id = ?", userID).Scan(&u.ID, &u.Username)
	if err != nil {
		c.JSON(404, gin.H{"error": "用户未找到"})
		return
	}
	c.JSON(200, u)
}

func listUsersHandler(c *gin.Context) {
	rows, err := db.Query("SELECT id, username, created_at FROM users")
	if err != nil {
		c.JSON(500, gin.H{"error": "Database error"})
		return
	}
	defer rows.Close()

	var users []gin.H
	for rows.Next() {
		var id int
		var username string
		var createdAt time.Time
		if err := rows.Scan(&id, &username, &createdAt); err != nil {
			continue
		}
		users = append(users, gin.H{
			"id":         id,
			"username":   username,
			"created_at": createdAt,
		})
	}
	if users == nil {
		users = []gin.H{}
	}
	c.JSON(200, users)
}

func deleteUserHandler(c *gin.Context) {
	id := c.Param("id")
	_, err := db.Exec("DELETE FROM users WHERE id = ?", id)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete user"})
		return
	}
	c.JSON(200, gin.H{"message": "User deleted"})
}

func updateUserHandler(c *gin.Context) {
	id := c.Param("id")
	var u struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&u); err != nil {
		c.JSON(400, gin.H{"error": "Invalid data"})
		return
	}

	if u.Password != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		_, err := db.Exec("UPDATE users SET username = ?, password = ? WHERE id = ?", u.Username, string(hash), id)
		if err != nil {
			c.JSON(500, gin.H{"error": "Update failed"})
			return
		}
	} else {
		_, err := db.Exec("UPDATE users SET username = ? WHERE id = ?", u.Username, id)
		if err != nil {
			c.JSON(500, gin.H{"error": "Update failed"})
			return
		}
	}

	c.JSON(200, gin.H{"message": "User updated"})
}

// --- Middleware ---

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("token")
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "未登录"})
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("user_id", claims["user_id"])
			c.Next()
		} else {
			c.AbortWithStatusJSON(401, gin.H{"error": "Token 无效"})
		}
	}
}
