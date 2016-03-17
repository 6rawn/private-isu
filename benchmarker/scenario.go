package main

import (
	"net/url"
	"time"

	"io"

	"errors"

	"github.com/PuerkitoBio/goquery"
	"github.com/catatsuy/private-isu/benchmarker/checker"
	"github.com/catatsuy/private-isu/benchmarker/util"
)

// 1ページに表示される画像にリクエストする
// TODO: 画像には並列リクエストするべきでは？
func loadImages(s *checker.Session, imageUrls []string) {
	for _, url := range imageUrls {
		imgReq := checker.NewAssetAction(url, &checker.Asset{})
		imgReq.Description = "投稿画像"
		imgReq.Play(s)
	}
}

func extractImages(body io.Reader) ([]string, error) {
	imageUrls := []string{}

	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return nil, errors.New("ページが正しく読み込めませんでした")
	}

	doc.Find("img.isu-image").Each(func(_ int, selection *goquery.Selection) {
		if url, ok := selection.Attr("src"); ok {
			imageUrls = append(imageUrls, url)
		}
	}).Length()

	return imageUrls, nil
}

func extractImagesAndPostLinks(body io.Reader) ([]string, []string, error) {
	imageUrls := []string{}
	postLinks := []string{}

	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return nil, nil, errors.New("ページが正しく読み込めませんでした")
	}

	doc.Find("img.isu-image").Each(func(_ int, selection *goquery.Selection) {
		if url, ok := selection.Attr("src"); ok {
			imageUrls = append(imageUrls, url)
		}
	}).Length()

	doc.Find("a.isu-post-permalink").Each(func(_ int, selection *goquery.Selection) {
		if url, ok := selection.Attr("href"); ok {
			postLinks = append(postLinks, url)
		}
	}).Length()

	return imageUrls, postLinks, nil
}

// 普通のページに表示されるべき静的ファイルに一通りアクセス
func loadAssets(s *checker.Session) {
	a := checker.NewAssetAction("/favicon.ico", &checker.Asset{})
	a.ExpectedLocation = "/favicon.ico"
	a.Description = "favicon.ico"
	a.Play(s)

	a = checker.NewAssetAction("js/jquery-2.2.0.js", &checker.Asset{})
	a.ExpectedLocation = "js/jquery-2.2.0.js"
	a.Description = "js/jquery-2.2.0.js"
	a.Play(s)

	a = checker.NewAssetAction("js/jquery.timeago.js", &checker.Asset{})
	a.ExpectedLocation = "js/jquery.timeago.js"
	a.Description = "js/jquery.timeago.js"
	a.Play(s)

	a = checker.NewAssetAction("js/jquery.timeago.ja.js", &checker.Asset{})
	a.ExpectedLocation = "js/jquery.timeago.ja.js"
	a.Description = "js/jquery.timeago.ja.js"
	a.Play(s)

	a = checker.NewAssetAction("/js/main.js", &checker.Asset{})
	a.ExpectedLocation = "/js/main.js"
	a.Description = "js/main.js"
	a.Play(s)

	a = checker.NewAssetAction("/css/style.css", &checker.Asset{})
	a.ExpectedLocation = "/css/style.css"
	a.Description = "/css/style.css"
	a.Play(s)
}

// インデックスにリクエストして「もっと見る」を最大10ページ辿る
// WaitAfterTimeout秒たったら問答無用で打ち切る
func indexMoreAndMoreScenario(s *checker.Session) {
	var imageUrls []string
	var err error
	start := time.Now()

	imagePerPageChecker := func(s *checker.Session, body io.Reader) error {
		imageUrls, err = extractImages(body)
		if err != nil {
			return err
		}
		if len(imageUrls) < PostsPerPage {
			return errors.New("1ページに表示される画像の数が足りません")
		}
		return nil
	}

	index := checker.NewAction("GET", "/")
	index.ExpectedLocation = "/"
	index.Description = "インデックスページ"
	index.CheckFunc = imagePerPageChecker
	index.Play(s)

	loadAssets(s)
	loadImages(s, imageUrls)

	offset := util.RandomNumber(10) // 10は適当。URLをバラけさせるため
	for i := 0; i < 10; i++ {       // 10ページ辿る
		maxCreatedAt := time.Date(2016, time.January, 2, 11, 46, 21-PostsPerPage*i+offset, 0, time.FixedZone("Asia/Tokyo", 9*60*60))

		imageUrls = []string{}
		posts := checker.NewAction("GET", "/posts?max_created_at="+url.QueryEscape(maxCreatedAt.Format(time.RFC3339)))
		posts.Description = "インデックスページの「もっと見る」"
		posts.CheckFunc = imagePerPageChecker
		posts.Play(s)

		loadImages(s, imageUrls)

		if time.Now().Sub(start) > WaitAfterTimeout {
			break
		}
	}
}

// インデックスページを5回表示するだけ（負荷かける用）
// WaitAfterTimeout秒たったら問答無用で打ち切る
func loadIndexScenario(s *checker.Session) {
	var imageUrls []string
	var err error
	start := time.Now()

	imagePerPageChecker := func(s *checker.Session, body io.Reader) error {
		imageUrls, err = extractImages(body)
		if err != nil {
			return err
		}
		if len(imageUrls) < PostsPerPage {
			return errors.New("1ページに表示される画像の数が足りません")
		}
		return nil
	}

	index := checker.NewAction("GET", "/")
	index.ExpectedLocation = "/"
	index.Description = "インデックスページ"
	index.CheckFunc = imagePerPageChecker
	index.Play(s)

	loadAssets(s)
	loadImages(s, imageUrls)

	for i := 0; i < 4; i++ {
		// あとの4回はDOMをパースしない。トップページをキャッシュして超高速に返されたとき対策
		index := checker.NewAction("GET", "/")
		index.ExpectedLocation = "/"
		index.Description = "インデックスページ"

		loadAssets(s)
		loadImages(s, imageUrls) // 画像は初回と同じものにリクエスト投げる

		if time.Now().Sub(start) > WaitAfterTimeout {
			break
		}
	}
}

// /@:account_name のページにアクセスして投稿ページをいくつか開いていく
// WaitAfterTimeout秒たったら問答無用で打ち切る
func userAndPostPageScenario(s *checker.Session, accountName string) {
	var imageUrls []string
	var postLinks []string
	var err error
	start := time.Now()

	userPage := checker.NewAction("GET", "/@"+accountName)
	userPage.Description = "ユーザーページ"
	userPage.CheckFunc = func(s *checker.Session, body io.Reader) error {
		imageUrls, postLinks, err = extractImagesAndPostLinks(body)
		if err != nil {
			return err
		}
		return nil
	}
	userPage.Play(s)

	loadAssets(s)
	loadImages(s, imageUrls)

	for _, link := range postLinks {
		postPage := checker.NewAction("GET", link)
		postPage.Description = "投稿単体ページ"
		postPage.CheckFunc = func(s *checker.Session, body io.Reader) error {
			imageUrls, err = extractImages(body)
			if err != nil {
				return err
			}
			if len(imageUrls) < 1 {
				return errors.New("投稿単体ページに投稿画像が表示されていません")
			}
			return nil
		}
		postPage.Play(s)

		loadAssets(s)
		loadImages(s, imageUrls)

		if time.Now().Sub(start) > WaitAfterTimeout {
			break
		}
	}
}

// ログインして /@:account_name のページにアクセスして一番上の投稿にコメントする
// 簡略化のために画像や静的ファイルへのアクセスはスキップする
func commentScenario(s *checker.Session, me user, accountName string, sentence string) {
	var csrfToken string
	var postID string
	var ok bool

	login := checker.NewAction("POST", "/login")
	login.ExpectedLocation = "/"
	login.Description = "ログインページ"
	login.PostData = map[string]string{
		"account_name": me.AccountName,
		"password":     me.Password,
	}
	login.Play(s)

	userPage := checker.NewAction("GET", "/@"+accountName)
	userPage.Description = "ユーザーページ"
	userPage.CheckFunc = func(s *checker.Session, body io.Reader) error {
		doc, err := goquery.NewDocumentFromReader(body)
		if err != nil {
			return errors.New("ページが正しく読み込めませんでした")
		}

		sel := doc.Find(`div.isu-post`).First()

		if sel.Length() == 0 {
			return nil // 1枚も投稿が無いユーザー
		}

		csrfToken, ok = sel.Find(`input[name="csrf_token"]`).First().Attr("value")
		if !ok {
			return errors.New("CSRFトークンが取得できません")
		}

		postID, ok = sel.Find(`input[name="post_id"]`).First().Attr("value")
		if !ok {
			return errors.New("post_idが取得できません")
		}

		return nil
	}
	userPage.Play(s)

	if postID == "" {
		return
	}

	comment := checker.NewAction("POST", "/comment")
	comment.ExpectedLocation = "/posts/" + postID
	comment.PostData = map[string]string{
		"post_id":    postID,
		"comment":    sentence,
		"csrf_token": csrfToken,
	}
	comment.Play(s)
}

// ログインして画像を投稿する
// 簡略化のために画像や静的ファイルへのアクセスはスキップする
func postImageScenario(s *checker.Session, me user, image *checker.Asset, sentence string) {
	var csrfToken string
	var imageUrls []string
	var ok bool
	var err error

	login := checker.NewAction("POST", "/login")
	login.ExpectedLocation = "/"
	login.Description = "ログインページ"
	login.PostData = map[string]string{
		"account_name": me.AccountName,
		"password":     me.Password,
	}
	login.CheckFunc = func(s *checker.Session, body io.Reader) error {
		doc, err := goquery.NewDocumentFromReader(body)
		if err != nil {
			return errors.New("ページが正しく読み込めませんでした")
		}

		csrfToken, ok = doc.Find(`input[name="csrf_token"]`).First().Attr("value")
		if !ok {
			return errors.New("CSRFトークンが取得できません")
		}

		return nil
	}
	login.Play(s)

	postImage := checker.NewUploadAction("POST", "/", "file")
	postImage.Description = "画像を投稿してリダイレクトされることを確認"
	postImage.Asset = image

	postImage.CheckFunc = func(s *checker.Session, body io.Reader) error {
		imageUrls, err = extractImages(body)
		if err != nil {
			return err
		}
		if len(imageUrls) < 1 {
			return errors.New("投稿した画像が表示されていません")
		}
		return nil
	}

	_, err = postImage.PlayWithURL(s)
	if err != nil {
		return // TODO: どういうエラーハンドリングが適切か考える
	}

	if len(imageUrls) < 1 {
		return // このケースは上のCheckFuncの中で既にエラーにしてある
	}

	getImage := checker.NewAssetAction(imageUrls[0], image)
	getImage.Description = "投稿した画像と一致することを確認"
}
