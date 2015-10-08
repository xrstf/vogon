package main

type configuration struct {
	Database struct {
		Source       string `json:"source"`
		PasswordFile string `json:"passwordFile"`
		DeleteOnBoot bool   `json:"deleteOnBoot"`
	} `json:"database"`

	SessionKey  string `json:"sessionKey"`
	CsrfKey     string `json:"csrfKey"`
	Environment string `json:"environment"`
}
