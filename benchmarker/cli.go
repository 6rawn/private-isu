package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/catatsuy/private-isu/benchmarker/score"
	"github.com/catatsuy/private-isu/benchmarker/util"
	"github.com/catatsuy/private-isu/benchmarker/worker"
)

// Exit codes are int values that represent an exit code for a particular error.
const (
	ExitCodeOK    int = 0
	ExitCodeError int = 1 + iota
)

// CLI is the command line object
type CLI struct {
	// outStream and errStream are the stdout and stderr
	// to write message from the CLI.
	outStream, errStream io.Writer
}

// Run invokes the CLI with the given arguments.
func (cli *CLI) Run(args []string) int {
	var (
		target string

		version bool
	)

	// Define option flag parse
	flags := flag.NewFlagSet(Name, flag.ContinueOnError)
	flags.SetOutput(cli.errStream)

	flags.StringVar(&target, "target", "", "")
	flags.StringVar(&target, "t", "", "(Short)")

	flags.BoolVar(&version, "version", false, "Print version information and quit.")

	// Parse commandline flag
	if err := flags.Parse(args[1:]); err != nil {
		return ExitCodeError
	}

	// Show version
	if version {
		fmt.Fprintf(cli.errStream, "%s version %s\n", Name, Version)
		return ExitCodeOK
	}

	worker.SetTargetHost(target)

	type user struct {
		AccountName string
		Password    string
	}
	users := []*user{
		&user{
			AccountName: "user1",
			Password:    "user1user1",
		},
		&user{
			AccountName: "user2",
			Password:    "user2user2",
		},
		&user{
			AccountName: "user3",
			Password:    "user3user3",
		},
		&user{
			AccountName: "user4",
			Password:    "user4user4",
		},
		&user{
			AccountName: "user5",
			Password:    "user5user5",
		},
	}
	adminUsers := []*user{
		&user{
			AccountName: "adminuser1",
			Password:    "adminuser1",
		},
		&user{
			AccountName: "adminuser2",
			Password:    "adminuser2",
		},
		&user{
			AccountName: "adminuser3",
			Password:    "adminuser3",
		},
		&user{
			AccountName: "adminuser4",
			Password:    "adminuser4",
		},
	}

	images := []*worker.Asset{
		&worker.Asset{
			MD5:  "8c4d0286cc2c92b418cb6b20fa2055d4",
			Path: "./userdata/img/Cb0e066UYAAwxtT.jpg",
		},
		&worker.Asset{
			MD5:  "e43267883243c297d8f6f66582fc098b",
			Path: "./userdata/img/Cb0rChYUUAAERl8.jpg",
		},
		&worker.Asset{
			MD5:  "623176077a8da7cc7602c132cb91deeb",
			Path: "./userdata/img/Cb5XdejUcAA78Nz.jpg",
		},
		&worker.Asset{
			MD5:  "45d7ba976202a85a90e17282d7f7a781",
			Path: "./userdata/img/CbJLMlcUcAER_Sg.jpg",
		},
		&worker.Asset{
			MD5:  "de906699516c228eee7f025d3e88057b",
			Path: "./userdata/img/CbOuZvjUEAA5r0K.jpg",
		},
		&worker.Asset{
			MD5:  "b50e41b163b501f1aa3cada9a21696c4",
			Path: "./userdata/img/CbT1pABVAAA1OMG.jpg",
		},
		&worker.Asset{
			MD5:  "aa7929fb4ec357063e12701226d0fa3d",
			Path: "./userdata/img/Cba_gezUMAApMPw.jpg",
		},
		&worker.Asset{
			MD5:  "a36c35c8db3e32bde24f9e77d811fecb",
			Path: "./userdata/img/CbyvdPtUcAMiasE.jpg",
		},
		&worker.Asset{
			MD5:  "5985d209ba9d3fe9c0ded4fdbf4cdeb5",
			Path: "./userdata/img/CcCJ26eVAAAf9sh.jpg",
		},
		&worker.Asset{
			MD5:  "c5e0fb9d1132ed936813c07c480730b9",
			Path: "./userdata/img/CcJYpMDUUAA2xXc.jpg",
		},
	}

	timeUp := time.After(30 * time.Second)
	done := make(chan bool)
	quit := false
	var mu sync.RWMutex

	workersC := make(chan *worker.Worker, 20)

	// workersCにworkerを用意しておく
	// キューとして使って並列度が高くなりすぎないようにするのと、
	// 時間が来たらcloseする
	go func() {
		for {
			workersC <- worker.NewWorker()
			mu.RLock()
			if quit {
				done <- true
				break
			}
			mu.RUnlock()
		}
	}()

	toppageNotLogin := genScenarioToppageNotLogin()

	// TOPページに非ログイン状態でひたすらアクセス
	// 画像にもリクエストを送っている
	go func() {
		for {
			toppageNotLogin.Play(<-workersC)
		}
	}()

	login := genScenarioLogin()
	mypage := genScenarioMyPage()

	// ログインしてmypageをちゃんと見れるか確認
	go func() {
		for {
			u := users[util.RandomNumber(len(users))]
			login.PostData = map[string]string{
				"account_name": u.AccountName,
				"password":     u.Password,
			}
			w := <-workersC
			login.Play(w)
			mypage.Play(w)
		}
	}()

	postTopImg := genScenarioPostTopImg()
	mypageCheck := genScenarioCheckMypage()

	getIndexAfterPostImg := genScenarioGetIndexAfterPostImg(postTopImg, mypageCheck)
	postComment := genScenarioPostComment()
	getIndexAfterPostComment := genScenarioGetIndexAfterPostComment(postComment)

	// ログインして、画像を投稿して、mypageをcheckして、コメントを投稿
	go func() {
		for {
			u := users[util.RandomNumber(len(users))]
			login.PostData = map[string]string{
				"account_name": u.AccountName,
				"password":     u.Password,
			}
			postTopImg.Asset = images[util.RandomNumber(len(images))]
			w := <-workersC
			login.Play(w)
			getIndexAfterPostImg.Play(w)
			getIndexAfterPostComment.Play(w)
		}
	}()

	postRegister := genScenarioPostRegister()

	interval := time.Tick(10 * time.Second)

	// ユーザーを作って、ログインして画像を投稿する
	// そのユーザーはBAN機能を使って消される
	go func() {
		for {
			w1 := <-workersC

			deletedStr := util.RandomLUNStr(25)
			deletedUser := map[string]string{
				"account_name": deletedStr,
				"password":     deletedStr,
			}

			postRegister.PostData = deletedUser
			postRegister.Play(w1)
			login.PostData = deletedUser
			login.Play(w1)
			postTopImg.Asset = images[util.RandomNumber(len(images))]
			getIndexAfterPostImg.Play(w1)
			postTopImg.PlayWithPostFile(w1, "file")

			u := adminUsers[util.RandomNumber(len(adminUsers))]
			login.PostData = map[string]string{
				"account_name": u.AccountName,
				"password":     u.Password,
			}
			w2 := <-workersC
			login.Play(w2)

			getAdminBanned := worker.NewScenario("GET", "/admin/banned")
			getAdminBanned.ExpectedStatusCode = 200
			getAdminBanned.ExpectedLocation = "/admin/banned"
			getAdminBanned.Checked = true
			getAdminBanned.CheckFunc = func(w *worker.Worker, body io.Reader) error {
				doc, _ := goquery.NewDocumentFromReader(body)
				token, _ := doc.Find(`input[name="csrf_token"]`).First().Attr("value")
				uid, _ := doc.Find(`input[data-account-name="` + deletedStr + `"]`).First().Attr("value")

				postAdminBanned := worker.NewScenario("POST", "/admin/banned")
				postAdminBanned.ExpectedStatusCode = 200
				postAdminBanned.ExpectedLocation = "/admin/banned"
				postAdminBanned.PostData = map[string]string{
					"uid[]":      uid,
					"csrf_token": token,
				}
				postAdminBanned.Play(w)

				return nil
			}
			getAdminBanned.Play(w2)

			checkBanned := worker.NewScenario("GET", "/")
			checkBanned.ExpectedStatusCode = 200
			checkBanned.Checked = true

			checkBanned.CheckFunc = func(w *worker.Worker, body io.Reader) error {
				doc, _ := goquery.NewDocumentFromReader(body)

				exit := 0
				existErr := false

				doc.Find(`.isu-post-account-name`).EachWithBreak(func(_ int, s *goquery.Selection) bool {
					account_name := strings.TrimSpace(s.Text())
					if account_name == deletedStr {
						existErr = true
						return false
					}
					if exit > 20 {
						return false
					} else {
						exit += 1
						return true
					}
					return true
				})

				if existErr {
					return fmt.Errorf("BANされたユーザーの投稿が表示されています")
				}

				return nil
			}
			checkBanned.Play(w2)
			<-interval
		}
	}()

	<-timeUp

	mu.Lock()
	quit = true
	mu.Unlock()

	<-done
	close(workersC)

	fmt.Printf("score: %d, suceess: %d, fail: %d\n",
		score.GetInstance().GetScore(),
		score.GetInstance().GetSucesses(),
		score.GetInstance().GetFails(),
	)

	for _, err := range worker.GetFails() {
		fmt.Println(err)
	}

	return ExitCodeOK
}

func genScenarioToppageNotLogin() *worker.Scenario {
	w := worker.NewScenario("GET", "/mypage")
	w.ExpectedStatusCode = 200
	w.ExpectedLocation = "/"
	w.Description = "/mypageは非ログイン時に/にリダイレクトがかかる"
	w.Checked = true
	w.CheckFunc = func(cw *worker.Worker, body io.Reader) error {
		doc, _ := goquery.NewDocumentFromReader(body)

		exit := 0
		doc.Find("img").EachWithBreak(func(_ int, s *goquery.Selection) bool {
			url, _ := s.Attr("src")
			imgReq := worker.NewScenario("GET", url)
			imgReq.ExpectedStatusCode = 200
			imgReq.Asset = &worker.Asset{}
			imgReq.PlayWithImage(cw)
			if exit > 15 {
				return false
			} else {
				exit += 1
				return true
			}
		})

		return nil
	}

	return w
}

func genScenarioMypageCheck() *worker.Scenario {
	w := worker.NewScenario("GET", "/mypage")
	w.ExpectedStatusCode = 200
	w.Checked = true

	w.CheckFunc = func(cw *worker.Worker, body io.Reader) error {
		doc, _ := goquery.NewDocumentFromReader(body)

		url, _ := doc.Find(`img`).First().Attr("src")
		imgReq := worker.NewScenario("GET", url)
		imgReq.ExpectedStatusCode = 200
		imgReq.Asset = &worker.Asset{}
		imgReq.PlayWithImage(cw)

		return nil
	}

	return w
}

func genScenarioLogin() *worker.Scenario {
	w := worker.NewScenario("POST", "/login")
	w.ExpectedStatusCode = 200
	w.ExpectedLocation = "/"
	w.Description = "ログイン"

	return w
}

func genScenarioMyPage() *worker.Scenario {
	w := worker.NewScenario("GET", "/mypage")
	w.ExpectedStatusCode = 200
	w.ExpectedLocation = "/mypage"
	w.Description = "ログインして、/mypageに"

	return w
}

func genScenarioPostTopImg() *worker.Scenario {
	w := worker.NewScenario("POST", "/")
	w.ExpectedStatusCode = 200
	w.ExpectedLocation = "/"
	w.Description = "画像を投稿"

	return w
}

func genScenarioCheckMypage() *worker.Scenario {
	w := worker.NewScenario("GET", "/mypage")
	w.ExpectedStatusCode = 200
	w.Checked = true

	w.CheckFunc = func(cw *worker.Worker, body io.Reader) error {
		doc, _ := goquery.NewDocumentFromReader(body)

		url, _ := doc.Find(`img`).First().Attr("src")
		imgReq := worker.NewScenario("GET", url)
		imgReq.ExpectedStatusCode = 200
		imgReq.Asset = &worker.Asset{}
		imgReq.PlayWithImage(cw)

		return nil
	}

	return w
}

func genScenarioPostComment() *worker.Scenario {
	w := worker.NewScenario("POST", "/comment")
	w.ExpectedStatusCode = 200
	w.ExpectedLocation = "/"

	return w
}

func genScenarioGetIndexAfterPostImg(postTopImg *worker.Scenario, mypageCheck *worker.Scenario) *worker.Scenario {
	w := worker.NewScenario("GET", "/")
	w.ExpectedStatusCode = 200
	w.Checked = true

	w.CheckFunc = func(cw *worker.Worker, body io.Reader) error {
		doc, _ := goquery.NewDocumentFromReader(body)

		token, _ := doc.Find(`input[name="csrf_token"]`).First().Attr("value")
		postTopImg.PostData = map[string]string{
			"body":       util.RandomLUNStr(util.RandomNumber(20) + 10),
			"csrf_token": token,
			"type":       "image/jpeg",
		}
		postTopImg.PlayWithPostFile(cw, "file")
		mypageCheck.Play(cw)

		return nil
	}

	return w
}

func genScenarioGetIndexAfterPostComment(postComment *worker.Scenario) *worker.Scenario {
	w := worker.NewScenario("GET", "/")
	w.ExpectedStatusCode = 200
	w.Checked = true

	w.CheckFunc = func(w *worker.Worker, body io.Reader) error {
		doc, _ := goquery.NewDocumentFromReader(body)

		token, _ := doc.Find(`input[name="csrf_token"]`).First().Attr("value")
		postID, _ := doc.Find(`input[name="post_id"]`).First().Attr("value")
		postComment.PostData = map[string]string{
			"post_id":    postID,
			"comment":    "comment",
			"csrf_token": token,
		}
		postComment.Play(w)

		return nil
	}
	return w
}

func genScenarioPostRegister() *worker.Scenario {
	w := worker.NewScenario("POST", "/register")
	w.ExpectedStatusCode = 200
	w.ExpectedLocation = "/"
	return w
}
