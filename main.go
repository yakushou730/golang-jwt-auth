package main

import (
	"database/sql"
	"golang-jwt-auth/controllers"
	"golang-jwt-auth/driver"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
)

var db *sql.DB

func init() {
	gotenv.Load()
}

func main() {
	db = driver.ConnectDB()
	controller := controllers.Controller{}

	router := mux.NewRouter()

	router.HandleFunc("/signup", controller.Signup(db)).Methods("POST")
	router.HandleFunc("/login", controller.Login(db)).Methods("POST")
	router.HandleFunc("/protected", controller.TokenVerifyMiddleWare(controller.ProectedEndpoint())).Methods("GET")

	log.Println("Listen on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))
}
