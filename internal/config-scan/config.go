package configscan

type ScannerConfig struct {
	userAccount *UserAccount
}

type UserAccount struct {
	Uid      string `json:"uid"`
	Username string `json:"username"`
}

func NewScannerConfig(userAccount *UserAccount) *ScannerConfig {
	return &ScannerConfig{
		userAccount: userAccount,
	}
}
