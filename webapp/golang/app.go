package main

import (
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	goMemcache "github.com/bradfitz/gomemcache/memcache"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/html"
	"github.com/jmoiron/sqlx"
)

var (
	db             *sqlx.DB
	sessionStore   *session.Store
	memcacheClient *goMemcache.Client
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []Comment
	User         User
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User
}

type CommentCounts struct {
	PostID int `db:"post_id"`
	Count  int `db:"count"`
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient = goMemcache.New(memdAddr)
	memcacheClient.Timeout = 5000 * time.Millisecond // 1s
	memcacheClient.MaxIdleConns = 100
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	// cacheStorage := memcache.New(memcache.Config{
	// 	Servers: memdAddr,
	// })
	sessionStore = session.New(session.Config{
		// Storage:   cacheStorage,
		KeyLookup: "cookie:isuconp-go.session",
	})
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexp.MustCompile(`\A[0-9a-zA-Z_]{3,}\z`).MatchString(accountName) &&
		regexp.MustCompile(`\A[0-9a-zA-Z_]{6,}\z`).MatchString(password)
}

// 今回のGo実装では言語側のエスケープの仕組みが使えないのでOSコマンドインジェクション対策できない
// 取り急ぎPHPのescapeshellarg関数を参考に自前で実装
// cf: http://jp2.php.net/manual/ja/function.escapeshellarg.php
func escapeshellarg(arg string) string {
	return "'" + strings.Replace(arg, "'", "'\\''", -1) + "'"
}

func digest(src string) string {
	// opensslのバージョンによっては (stdin)= というのがつくので取る
	out, err := exec.Command("/bin/bash", "-c", `printf "%s" `+escapeshellarg(src)+` | openssl dgst -sha512 | sed 's/^.*= //'`).Output()
	if err != nil {
		log.Print(err)
		return ""
	}

	return strings.TrimSuffix(string(out), "\n")
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(c *fiber.Ctx) *session.Session {
	session, err := sessionStore.Get(c)
	if err != nil {
		log.Println("getSession", err)
		panic(err)
	}

	return session
}

func getSessionUser(r *fiber.Ctx) User {
	session := getSession(r)

	uid := session.Get("user_id")
	if uid == nil {
		return User{}
	}

	u := User{}

	err := db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", uid)
	if err != nil {
		return User{}
	}

	return u
}

func getFlash(c *fiber.Ctx, key string) string {
	session := getSession(c)

	value := session.Get(key)

	if value == nil {
		return ""
	}

	session.Delete(key)
	session.Save()

	return value.(string)
}

func getUsersFromDB(userIds []string) ([]User, error) {
	users := make([]User, 0, len(userIds))

	err := db.Select(&users, fmt.Sprintf("SELECT * FROM users WHERE id IN (%s)", strings.Join(userIds, ", ")))
	if err != nil {
		return nil, err
	}

	return users, nil
}

func getUsersFromCache(userIds []string) (map[string]User, error) {
	users := map[string]User{}
	userMap, err := memcacheClient.GetMulti(userIds)
	if err != nil {
		return nil, err
	}

	notFoundUserIds := []string{}
	for _, userId := range userIds {
		rawUser, ok := userMap[userId]
		if !ok {
			notFoundUserIds = append(notFoundUserIds, userId)
			continue
		}

		user := &User{}
		err := json.Unmarshal(rawUser.Value, &user)
		if err != nil {
			return nil, err
		}
		users[userId] = *user
	}

	if len(notFoundUserIds) > 0 {
		_users, err := getUsersFromDB(notFoundUserIds)
		if err != nil {
			return nil, err
		}
		for _, user := range _users {
			rawUser, err := json.Marshal(&user)
			if err != nil {
				return nil, err
			}

			key := strconv.Itoa(user.ID)
			err = memcacheClient.Set(&goMemcache.Item{
				Key:   key,
				Value: rawUser,
			})
			if err != nil {
				return nil, err
			}

			users[strconv.Itoa(user.ID)] = user
		}
	}

	return users, nil
}

func getUsers(userIds []string) (map[string]User, error) {
	users, err := getUsersFromCache(userIds)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func getCommentCountsFromDB(postIds []string) ([]CommentCounts, error) {
	var commentCounts []CommentCounts
	query := fmt.Sprintf("SELECT post_id, COUNT(*) AS `count` FROM `comments` WHERE `post_id` IN (%s) GROUP BY post_id", strings.Join(postIds, ", "))
	err := db.Select(&commentCounts, query)
	if err != nil {
		return nil, err
	}
	return commentCounts, nil
}

func getCommentCountsFromCache(postIds []int) (map[int]int, error) {
	keys := []string{}

	for _, postId := range postIds {
		keys = append(keys, fmt.Sprintf("comments_count_%d", postId))
	}

	items, err := memcacheClient.GetMulti(keys)
	if err != nil {
		return nil, err
	}

	counts := map[int]int{}
	notFoundPostIds := []string{}
	for index, postId := range postIds {
		item, ok := items[keys[index]]
		if !ok {
			notFoundPostIds = append(notFoundPostIds, strconv.Itoa(postId))
			continue
		}

		var count int
		if err := json.Unmarshal(item.Value, &count); err != nil {
			return nil, err
		}

		counts[postId] = count
	}

	if len(notFoundPostIds) > 0 {
		comments, err := getCommentCountsFromDB(notFoundPostIds)
		if err != nil {
			return nil, err
		}

		for _, comment := range comments {
			rawComment, err := json.Marshal(comment.Count)
			if err != nil {
				return nil, err
			}

			err = memcacheClient.Set(&memcache.Item{
				Key:   fmt.Sprintf("comments_count_%d", comment.PostID),
				Value: rawComment,
			})
			if err != nil {
				return nil, err
			}

			counts[comment.PostID] = comment.Count
		}
	}

	return counts, nil
}

func getCommentsFromDB(postId int, allComments bool) ([]Comment, error) {
	query := "SELECT c.id, c.post_id, c.user_id, c.comment, c.created_at, u.account_name FROM comments AS c FORCE INDEX (post_id_idx) INNER JOIN users AS u ON c.user_id = u.id WHERE post_id = ? ORDER BY created_at DESC"
	if !allComments {
		query += " LIMIT 3"
	}

	var comments []Comment
	err := db.Select(&comments, query, postId)
	if err != nil {
		return nil, err
	}

	// reverse
	for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
		comments[i], comments[j] = comments[j], comments[i]
	}

	return comments, nil
}

func getCommentsFromCache(postIds []int, allComments bool) (map[int][]Comment, error) {
	suffix := "limited"
	if allComments {
		suffix = "all"
	}

	keys := []string{}
	for _, postId := range postIds {
		keys = append(keys, fmt.Sprintf("comments_%d_%s", postId, suffix))
	}

	items, err := memcacheClient.GetMulti(keys)
	if err != nil {
		return nil, err
	}

	comments := map[int][]Comment{}
	notFoundPostIds := []int{}
	for index, postId := range postIds {
		rawComment, ok := items[keys[index]]
		if !ok {
			notFoundPostIds = append(notFoundPostIds, postId)
			continue
		}

		var cc []Comment
		if err := json.Unmarshal(rawComment.Value, &cc); err != nil {
			return nil, err
		}

		comments[postId] = cc
	}

	for _, postId := range notFoundPostIds {
		cc, err := getCommentsFromDB(postId, allComments)
		if err != nil {
			return nil, err
		}

		rowCc, err := json.Marshal(cc)
		if err != nil {
			return nil, err
		}

		err = memcacheClient.Set(&memcache.Item{
			Key:   fmt.Sprintf("comments_%d_%s", postId, suffix),
			Value: rowCc,
		})
		if err != nil {
			return nil, err
		}

		comments[postId] = cc
	}

	return comments, nil
}

func makePosts(results []Post, csrfToken string, allComments bool) ([]Post, error) {
	var posts []Post

	postIds := []int{}
	for _, p := range results {
		postIds = append(postIds, p.ID)
	}

	counts, err := getCommentCountsFromCache(postIds)
	if err != nil {
		return nil, err
	}

	comments, err := getCommentsFromCache(postIds, allComments)
	if err != nil {
		return nil, err
	}

	for _, p := range results {
		p.CommentCount = counts[p.ID]
		p.Comments = comments[p.ID]
		p.CSRFToken = csrfToken
		posts = append(posts, p)
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(c *fiber.Ctx) string {
	session := getSession(c)
	csrfToken := session.Get("csrf_token")
	if csrfToken == nil {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(c *fiber.Ctx) error {
	dbInitialize()
	c.Status(http.StatusOK)
	return nil
}

func getLogin(c *fiber.Ctx) error {
	me := getSessionUser(c)

	if isLogin(me) {
		c.Redirect("/", http.StatusFound)
		return nil
	}

	return c.Render("login", fiber.Map{
		"Me":    me,
		"Flash": getFlash(c, "notice"),
	}, "layout")
}

func postLogin(c *fiber.Ctx) error {
	if isLogin(getSessionUser(c)) {
		c.Redirect("/", http.StatusFound)
		return nil
	}

	u := tryLogin(c.FormValue("account_name"), c.FormValue("password"))

	session := getSession(c)
	if u != nil {
		session.Set("user_id", u.ID)
		session.Set("csrf_token", secureRandomStr(16))
		session.Save()

		c.Redirect("/", http.StatusFound)
		return nil
	}

	session.Set("notice", "アカウント名かパスワードが間違っています")
	session.Save()

	c.Redirect("/login", http.StatusFound)
	return nil
}

func getRegister(c *fiber.Ctx) error {
	if isLogin(getSessionUser(c)) {
		c.Redirect("/", http.StatusFound)
		return nil
	}

	return c.Render("register", fiber.Map{
		"Me":    User{},
		"Flash": getFlash(c, "notice"),
	}, "layout")
}

func postRegister(c *fiber.Ctx) error {
	if isLogin(getSessionUser(c)) {
		c.Redirect("/", http.StatusFound)
		return nil
	}

	accountName, password := c.FormValue("account_name"), c.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(c)
		session.Set("notice", "アカウント名は3文字以上、パスワードは6文字以上である必要があります")
		session.Save()

		c.Redirect("/register", http.StatusFound)
		return nil
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(c)
		session.Set("notice", "アカウント名がすでに使われています")
		session.Save()

		c.Redirect("/register", http.StatusFound)
		return nil
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		c.Status(http.StatusInternalServerError)
		log.Print(err)
		return nil
	}

	session := getSession(c)
	uid, err := result.LastInsertId()
	if err != nil {
		c.Status(http.StatusInternalServerError)
		log.Print(err)
		return nil
	}
	session.Set("user_id", uid)
	session.Set("csrf_token", secureRandomStr(16))
	session.Save()

	c.Redirect("/", http.StatusFound)
	return nil
}

func getLogout(c *fiber.Ctx) error {
	session := getSession(c)
	session.Delete("user_id")
	session.Regenerate()
	session.Save()

	c.Redirect("/", http.StatusFound)
	return nil
}

func getIndex(c *fiber.Ctx) error {
	me := getSessionUser(c)

	results := []Post{}

	err := db.Select(&results, "SELECT id, user_id, body, mime, created_at FROM posts WHERE user_id IN (SELECT id FROM users WHERE del_flg = 0) ORDER BY created_at DESC LIMIT ?", postsPerPage)
	if err != nil {
		c.Status(http.StatusForbidden)
		log.Print(err)
		return nil
	}

	posts, err := makePosts(results, getCSRFToken(c), false)
	if err != nil {
		c.Status(http.StatusForbidden)
		log.Print(err)
		return nil
	}

	return c.Render("index", fiber.Map{
		"Posts":     posts,
		"Me":        me,
		"CSRFToken": getCSRFToken(c),
		"Flash":     getFlash(c, "notice"),
	}, "layout")
}

func getAccountName(c *fiber.Ctx) error {
	accountName := c.Params("accountName")
	user := User{}

	err := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		log.Print(err)
		return nil
	}

	if user.ID == 0 {
		c.Status(http.StatusNotFound)
		return nil
	}

	results := []Post{}

	err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC", user.ID)
	if err != nil {
		log.Print(err)
		return err
	}

	posts, err := makePosts(results, getCSRFToken(c), false)
	if err != nil {
		log.Print(err)
		return err
	}

	commentCount := 0
	err = db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return err
	}

	postIDs := []int{}
	err = db.Select(&postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	if err != nil {
		log.Print(err)
		return err
	}
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		s := []string{}
		for range postIDs {
			s = append(s, "?")
		}
		placeholder := strings.Join(s, ", ")

		// convert []int -> []interface{}
		args := make([]interface{}, len(postIDs))
		for i, v := range postIDs {
			args[i] = v
		}

		err = db.Get(&commentedCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN ("+placeholder+")", args...)
		if err != nil {
			log.Print(err)
			return err
		}
	}

	me := getSessionUser(c)

	return c.Render("user", fiber.Map{
		"Posts":          posts,
		"User":           user,
		"PostCount":      postCount,
		"CommentedCount": commentedCount,
		"Me":             me,
	}, "layout")
}

func getPosts(c *fiber.Ctx) error {
	maxCreatedAt := c.Query("max_created_at")
	if maxCreatedAt == "" {

		return nil
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return nil
	}

	results := []Post{}
	err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `created_at` <= ? ORDER BY `created_at` DESC", t.Format(ISO8601Format))
	if err != nil {
		log.Print(err)
		return err
	}

	posts, err := makePosts(results, getCSRFToken(c), false)
	if err != nil {
		log.Print(err)
		return err
	}

	if len(posts) == 0 {
		c.Status(http.StatusNotFound)
		return nil
	}

	return c.Render("posts", posts)
}

func getPostsID(c *fiber.Ctx) error {
	pidStr := c.Params("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		c.Status(http.StatusNotFound)
		return err
	}

	results := []Post{}
	err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return err
	}

	posts, err := makePosts(results, getCSRFToken(c), true)
	if err != nil {
		log.Print(err)
		return err
	}

	if len(posts) == 0 {
		c.Status(http.StatusNotFound)
		return errors.New("not found posts")
	}

	p := posts[0]

	me := getSessionUser(c)

	return c.Render("post_id", fiber.Map{
		"Post": p,
		"Me":   me,
	}, "layout")
}

func postIndex(c *fiber.Ctx) error {
	me := getSessionUser(c)
	if !isLogin(me) {
		c.Redirect("/login", http.StatusFound)
		return nil
	}

	if c.FormValue("csrf_token") != getCSRFToken(c) {
		c.Status(http.StatusUnprocessableEntity)
		return nil
	}

	file, err := c.FormFile("file")
	if err != nil {
		session := getSession(c)
		session.Set("notice", "画像が必須です")
		session.Save()

		c.Redirect("/", http.StatusFound)
		return nil
	}

	mime := ""
	ext := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := file.Header.Get("Content-Type")
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
			ext = "jpg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
			ext = "png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
			ext = "gif"
		} else {
			session := getSession(c)
			session.Set("notice", "投稿できる画像形式はjpgとpngとgifだけです")
			session.Save()

			c.Redirect("/", http.StatusFound)
			return nil
		}
	}

	if file.Size > UploadLimit {
		session := getSession(c)
		session.Set("notice", "ファイルサイズが大きすぎます")
		session.Save()

		c.Redirect("/", http.StatusFound)
		return nil
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `body`) VALUES (?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		c.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return err
	}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return err
	}

	fileName := fmt.Sprintf("../public/image/%d.%v", pid, ext)
	if err := c.SaveFile(file, fileName); err != nil {
		log.Print(err)
		return err
	}

	c.Redirect("/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
	return nil
}

func getImage(c *fiber.Ctx) error {
	pidStr := c.Params("id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		c.Status(http.StatusNotFound)
		return nil
	}

	post := Post{}
	err = db.Get(&post, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return err
	}

	ext := c.Params("ext")

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		c.Append("Content-Type", post.Mime)
		_, err := c.Write(post.Imgdata)
		if err != nil {
			log.Print(err)
			return err
		}
		return nil
	}

	c.Status(http.StatusNotFound)
	return nil
}

func postComment(c *fiber.Ctx) error {
	me := getSessionUser(c)
	if !isLogin(me) {
		c.Redirect("/login", http.StatusFound)
		return nil
	}

	if c.FormValue("csrf_token") != getCSRFToken(c) {
		c.Status(http.StatusUnprocessableEntity)
		return nil
	}

	postID, err := strconv.Atoi(c.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return err
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	_, err = db.Exec(query, postID, me.ID, c.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return err
	}

	c.Redirect(fmt.Sprintf("/posts/%d", postID), http.StatusFound)
	return nil
}

func getAdminBanned(c *fiber.Ctx) error {
	me := getSessionUser(c)
	if !isLogin(me) {
		c.Redirect("/", http.StatusFound)
		return nil
	}

	if me.Authority == 0 {
		c.Status(http.StatusForbidden)
		return nil
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return err
	}

	return c.Render("banned", fiber.Map{
		"Users":     users,
		"Me":        me,
		"CSRFToken": getCSRFToken(c),
	}, "layout")
}

func postAdminBanned(c *fiber.Ctx) error {
	me := getSessionUser(c)
	if !isLogin(me) {
		c.Redirect("/", http.StatusFound)
		return nil
	}

	if me.Authority == 0 {
		c.Status(http.StatusForbidden)
		return nil
	}

	if c.FormValue("csrf_token") != getCSRFToken(c) {
		c.Status(http.StatusUnprocessableEntity)
		return nil
	}

	query := "UPDATE `users` SET `del_flg` = ? WHERE `id` = ?"

	uid := c.Query("uid[]")

	for _, id := range strings.Split(uid, ",") {
		db.Exec(query, 1, id)
	}

	c.Redirect("/admin/banned", http.StatusFound)
	return nil
}

func main() {
	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	engine := html.New("./templates", ".html")
	engine.AddFunc("imageURL", imageURL)

	app := fiber.New(fiber.Config{
		// Prefork:     true,
		Views: engine,
	})

	app.Get("/initialize", getInitialize)
	app.Get("/login", getLogin)
	app.Post("/login", postLogin)
	app.Get("/register", getRegister)
	app.Post("/register", postRegister)
	app.Get("/logout", getLogout)
	app.Get("/", getIndex)
	app.Get("/posts", getPosts)
	app.Get("/posts/:id", getPostsID)
	app.Post("/", postIndex)
	app.Get("/image/:id.:ext", getImage)
	app.Post("/comment", postComment)
	app.Get("/admin/banned", getAdminBanned)
	app.Post("/admin/banned", postAdminBanned)
	app.Get(`/@:accountName<regex([a-zA-Z]+)>`, getAccountName)
	app.Static("/css", "../public/css")
	app.Static("/img", "../public/img")
	app.Static("/js", "../public/js")
	app.Static("/favicon.ico", "../public/favicon.ico")

	log.Fatal(app.Listen(":8080"))
}
