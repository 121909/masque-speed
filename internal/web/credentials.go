package web

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"fofa-masque/internal/model"
)

var errCredentials = errors.New("credentials could not be accessed")

func loadCredentials(path string) (model.Credentials, error) {
	var credentials model.Credentials
	f, err := os.Open(path)
	if err != nil {
		return credentials, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, 65537))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil {
		return model.Credentials{}, errCredentials
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return model.Credentials{}, errCredentials
	}
	return credentials, nil
}

// saveCredentials never removes the previous file before committing its replacement.
func saveCredentials(path string, credentials model.Credentials) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return errCredentials
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return errCredentials
	}
	file, err := os.CreateTemp(directory, ".credentials-*")
	if err != nil {
		return errCredentials
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return errCredentials
	}
	if err := json.NewEncoder(file).Encode(credentials); err != nil {
		return errCredentials
	}
	if err := file.Sync(); err != nil {
		return errCredentials
	}
	if err := file.Close(); err != nil {
		return errCredentials
	}
	if err := os.Rename(temporary, path); err != nil {
		return errCredentials
	}
	return nil
}
