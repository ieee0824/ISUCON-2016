package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"

	"encoding/json"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/unrolled/render"
)

var (
	baseUrl *url.URL
	db      *sql.DB
	re      *render.Render
)

func initializeHandler(w http.ResponseWriter, r *http.Request) {
	_, err := db.Exec("TRUNCATE star")
	panicIf(err)
	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func starsHandler(w http.ResponseWriter, r *http.Request) {
	var keywords []string
	json.Unmarshal([]byte(r.FormValue("keyword")), &keywords)
	//rows, err := db.Query(`SELECT SQL_CACHE * FROM star WHERE keyword = ?`, keyword)
	rows, err := db.Query(`SELECT * FROM star`)
	if err != nil && err != sql.ErrNoRows {
		panicIf(err)
		return
	}

	wkt := map[string]bool{}
	for _, keyword := range keywords {
		wkt[keyword] = true
	}

	stars := map[string][]Star{}
	for rows.Next() {
		s := Star{}
		err := rows.Scan(&s.ID, &s.Keyword, &s.UserName, &s.CreatedAt)
		panicIf(err)
		if _, ok := wkt[s.Keyword]; ok {
			//stars = append(stars, s)
			stars[s.Keyword] = append(stars[s.Keyword], s)
		}
	}
	rows.Close()

	bin, _ := json.Marshal(stars)

	w.Header().Set("Content-Type", "application/json")
	w.Write(bin)

	/*
		re.JSON(w, http.StatusOK, map[string][]Star{
			"result": stars,
		})
	*/
}

func starsPostHandler(w http.ResponseWriter, r *http.Request) {
	keyword := r.FormValue("keyword")

	origin := os.Getenv("ISUDA_ORIGIN")
	if origin == "" {
		origin = "http://localhost:5000"
	}
	u, err := r.URL.Parse(origin + "/keyword/" + pathURIEscape(keyword))
	panicIf(err)
	resp, err := http.Get(u.String())
	panicIf(err)
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		notFound(w)
		return
	}

	user := r.FormValue("user")
	_, err = db.Exec(`INSERT INTO star (keyword, user_name, created_at) VALUES (?, ?, NOW())`, keyword, user)
	panicIf(err)

	re.JSON(w, http.StatusOK, map[string]string{"result": "ok"})
}

func main() {
	runtime.GOMAXPROCS(1)
	host := os.Getenv("ISUTAR_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	portstr := os.Getenv("ISUTAR_DB_PORT")
	if portstr == "" {
		portstr = "3306"
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUTAR_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUTAR_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUTAR_DB_PASSWORD")
	dbname := os.Getenv("ISUTAR_DB_NAME")
	if dbname == "" {
		dbname = "isutar"
	}

	db, err = sql.Open("mysql", fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?loc=Local&parseTime=true",
		user, password, host, port, dbname,
	))
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	db.Exec("SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'")
	db.Exec("SET NAMES utf8mb4")

	re = render.New(render.Options{Directory: "dummy"})

	r := mux.NewRouter()
	r.HandleFunc("/initialize", myHandler(initializeHandler))
	s := r.PathPrefix("/stars").Subrouter()
	s.Methods("GET").HandlerFunc(myHandler(starsHandler))
	s.Methods("POST").HandlerFunc(myHandler(starsPostHandler))

	log.Fatal(http.ListenAndServe(":5001", r))
}
