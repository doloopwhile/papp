package main

import (
	"net/http"
	"text/template"

	"github.com/gorilla/context"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/jameskeane/bcrypt"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
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

func getSession(c web.C) *sessions.Session {
	return c.Env["Session"].(*sessions.Session)
}

func logout(c web.C, w http.ResponseWriter, r *http.Request) {
	session := getSession(c)
	session.Values["User"] = nil
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func register(c web.C, w http.ResponseWriter, r *http.Request) {
	session := getSession(c)

	c.Env["Flashes"] = session.Flashes("auth")
	err := tmpl.ExecuteTemplate(w, "register.tmpl", c.Env)
	if err != nil {
		panic(err)
	}
}

func registerPost(c web.C, w http.ResponseWriter, r *http.Request) {
	session := getSession(c)

	r.ParseForm()
	name, password := r.FormValue("user_name"), r.FormValue("password")

	for _, user := range users {
		if user.Name == name {
			session.AddFlash("user is already registered", "auth")
			register(c, w, r)
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
	c.Env["User"] = user

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func index(c web.C, w http.ResponseWriter, r *http.Request) {
	err := tmpl.ExecuteTemplate(w, "index.tmpl", c.Env)
	if err != nil {
		panic(err)
	}
}

func main() {
	tmpl = template.Must(template.ParseGlob("templates/*.tmpl"))

	key := securecookie.GenerateRandomKey(10)
	sessionStore := sessions.NewCookieStore(key)

	goji.Use(func(c *web.C, h http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			session, _ := sessionStore.Get(r, "session")
			c.Env["Session"] = session
			h.ServeHTTP(w, r)
			context.Clear(r)
		}
		return http.HandlerFunc(fn)
	})

	goji.Get("/", index)
	goji.Get("/logout", logout)
	goji.Get("/register", register)
	goji.Post("/register", registerPost)
	goji.Serve()
}
