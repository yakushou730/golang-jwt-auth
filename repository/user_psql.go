package repository

import (
	"database/sql"
	"golang-jwt-auth/models"
	"log"
)

type UserRepository struct{}

func logFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func (u UserRepository) Signup(db *sql.DB, user models.User) models.User {
	err := db.QueryRow("INSERT INTO users(email, password) VALUES($1, $2) RETURNING id;",
		user.Email, user.Password).Scan(&user.ID)

	logFatal(err)

	user.Password = ""
	return user
}

func (u UserRepository) Login(db *sql.DB, user models.User) (models.User, error) {
	rows := db.QueryRow("SELECT * FROM users WHERE email = $1", user.Email)
	err := rows.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		return user, err
	}
	return user, nil
}
