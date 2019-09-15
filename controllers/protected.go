package controllers

import (
	"golang-jwt-auth/utils"
	"net/http"
)

type Controller struct{}

func (c Controller) ProectedEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		utils.ResponseJSON(w, "Yes")
	}
}
