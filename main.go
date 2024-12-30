package main

import (
	"log"
	"net/http"
	"newProject/auth"
)

func main() {
	http.HandleFunc("/login", auth.LoginHandler)
	http.HandleFunc("/protected", auth.ProtectedHandler)

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}