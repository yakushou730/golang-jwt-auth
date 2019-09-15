package controllers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"golang-jwt-auth/models"
	"golang-jwt-auth/repository"
	"golang-jwt-auth/utils"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

func (c Controller) Signup(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		json.NewDecoder(r.Body).Decode(&user)

		if user.Email == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Email is missing.")
			return
		}
		if user.Password == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Password is missing.")
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

		if err != nil {
			log.Fatal(err)
		}

		user.Password = string(hash)

		userRepo := repository.UserRepository{}
		user = userRepo.Signup(db, user)

		if err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Server error.")
			return
		}

		user.Password = ""
		utils.ResponseJSON(w, user)
	}
}

func (c Controller) Login(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user models.User
		var jwt models.JWT

		json.NewDecoder(r.Body).Decode(&user)

		if user.Email == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Email is missing.")
			return
		}
		if user.Password == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Password is missing.")
			return
		}

		password := user.Password

		userRepo := repository.UserRepository{}
		user, err := userRepo.Login(db, user)

		hashedPassword := user.Password

		if err != nil {
			log.Fatal(err)
		}

		token, err := utils.GenerateToken(user)

		if err != nil {
			log.Fatal(err)
		}

		isValidPassword := utils.ComparePasswords(hashedPassword, []byte(password))

		if isValidPassword {
			w.WriteHeader(200)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Authorization", token)

			jwt.Token = token
			utils.ResponseJSON(w, jwt)
		} else {
			utils.RespondWithError(w, http.StatusUnauthorized, "Invalid Password")
		}
	}
}

func (c Controller) TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearerToken := r.Header.Get("Authorization")
		var authorizationHeader string

		if bearerToken != "" {
			authorizationHeader = strings.Split(bearerToken, " ")[1]
		}

		if authorizationHeader != "" {
			if len(authorizationHeader) > 2 {
				token, error := jwt.Parse(authorizationHeader, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte(os.Getenv("SECRET")), nil
				})

				if error != nil {
					utils.RespondWithError(w, http.StatusUnauthorized, error.Error())
					return
				}

				if token.Valid {
					next.ServeHTTP(w, r)
				} else {
					utils.RespondWithError(w, http.StatusUnauthorized, error.Error())
					return
				}
			}
		} else {
			utils.RespondWithError(w, http.StatusUnauthorized, "No Authorization")
		}
	})
}
