package auth

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/protected", protectedHandler)

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}