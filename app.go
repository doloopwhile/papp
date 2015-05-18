package main

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"os"
	"text/template"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	// "github.com/gorilla/securecookie"
	"github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
	"github.com/jameskeane/bcrypt"
)

type (
	User struct {
		Name           string
		HashedPassword string
	}
)

var (
	users []*User
	tmpl  *template.Template
)

func init() {
	gob.Register(User{})
}
func logout(w http.ResponseWriter, r *http.Request) {
	session := sessions.GetSession(r)
	session.Set("User", nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func register(w http.ResponseWriter, r *http.Request) {
	session := sessions.GetSession(r)

	data := map[string]interface{}{
		"User":    session.Get("User"),
		"Flashes": session.Flashes("auth"),
	}
	err := tmpl.ExecuteTemplate(w, "register.tmpl", data)
	if err != nil {
		panic(err)
	}
}

func registerPost(w http.ResponseWriter, r *http.Request) {
	session := sessions.GetSession(r)

	r.ParseForm()
	name, password := r.FormValue("user_name"), r.FormValue("password")

	for _, user := range users {
		if user.Name == name {
			session.AddFlash("user is already registered", "auth")
			register(w, r)
			return
		}
	}

	user := &User{Name: name}
	var err error
	if user.HashedPassword, err = bcrypt.Hash(password); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	users = append(users, user)
	session.Set("User", user)
	fmt.Println(session.Get("User"))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func index(w http.ResponseWriter, r *http.Request) {
	session := sessions.GetSession(r)

	data := map[string]interface{}{"User": session.Get("User")}
	fmt.Println(session.Get("User"))
	err := tmpl.ExecuteTemplate(w, "index.tmpl", data)
	if err != nil {
		panic(err)
	}
}

func main() {
	n := negroni.Classic()
	tmpl = template.Must(template.ParseGlob("templates/*.tmpl"))

	sessionStore := cookiestore.New([]byte("secret123"))
	n.Use(sessions.Sessions("login", sessionStore))

	r := mux.NewRouter()
	r.HandleFunc("/", index).Methods("GET")
	r.HandleFunc("/logout", logout).Methods("GET")
	r.HandleFunc("/register", register).Methods("GET")
	r.HandleFunc("/register", registerPost).Methods("POST")
	n.UseHandler(r)

	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "3000"
	}
	n.Run(":" + port)
}
