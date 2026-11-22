package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/getlantern/radiance/account"
	"github.com/getlantern/radiance/ipc"
)

type AccountCmd struct {
	Login   *LoginCmd          `arg:"subcommand:login" help:"log in to your account"`
	Logout  *LogoutCmd         `arg:"subcommand:logout" help:"log out of your account"`
	Signup  *SignupCmd         `arg:"subcommand:signup" help:"create a new account"`
	Recover *RecoverAccountCmd `arg:"subcommand:recover" help:"recover existing account"`

	Usage    *UsageCmd    `arg:"subcommand:usage" help:"view data usage"`
	Devices  *DevicesCmd  `arg:"subcommand:devices" help:"manage user devices"`
	SetEmail *SetEmailCmd `arg:"subcommand:set-email" help:"change account email"`
}

type LoginCmd struct {
	OAuth    bool   `arg:"--oauth" help:"log in with OAuth provider"`
	Provider string `arg:"--provider" help:"OAuth provider"`
}

type LogoutCmd struct{}

type SignupCmd struct{}

type RecoverAccountCmd struct{}

type SetEmailCmd struct{}

type UsageCmd struct{}

type DevicesCmd struct {
	List   bool   `arg:"-l,--list" help:"list user devices"`
	Remove string `arg:"-r,--remove" help:"remove a device by ID"`
}

func runAccount(ctx context.Context, c *ipc.Client, cmd *AccountCmd) error {
	switch {
	case cmd.Login != nil:
		return accountLogin(ctx, c, cmd.Login)
	case cmd.Logout != nil:
		return accountLogout(ctx, c)
	case cmd.Signup != nil:
		return accountSignup(ctx, c)
	case cmd.Recover != nil:
		return accountRecover(ctx, c)
	case cmd.Usage != nil:
		return accountDataUsage(ctx, c)
	case cmd.Devices != nil:
		return accountDevices(ctx, c, cmd.Devices)
	case cmd.SetEmail != nil:
		return accountSetEmail(ctx, c)
	default:
		return fmt.Errorf("no subcommand specified")
	}
}

// isLoggedIn returns the current user's email if logged in, or empty string if not.
func isLoggedIn(ctx context.Context, c *ipc.Client) (string, error) {
	userData, err := c.UserData(ctx)
	if err != nil {
		return "", err
	}
	return userData.GetLegacyUserData().GetEmail(), nil
}

func requireLoggedOut(ctx context.Context, c *ipc.Client) error {
	email, err := isLoggedIn(ctx, c)
	if err != nil {
		return fmt.Errorf("failed to check login status: %w", err)
	}
	if email != "" {
		return fmt.Errorf("already logged in as %s — log out first", email)
	}
	return nil
}

func requireLoggedIn(ctx context.Context, c *ipc.Client) (string, error) {
	email, err := isLoggedIn(ctx, c)
	if err != nil {
		return "", fmt.Errorf("failed to check login status: %w", err)
	}
	if email == "" {
		return "", fmt.Errorf("no user is currently logged in")
	}
	return email, nil
}

func accountLogin(ctx context.Context, c *ipc.Client, cmd *LoginCmd) error {
	if err := requireLoggedOut(ctx, c); err != nil {
		return err
	}

	if cmd.OAuth {
		provider := cmd.Provider
		if provider == "" {
			provider = "google"
		}
		url, err := c.OAuthLoginURL(ctx, provider)
		if err != nil {
			return err
		}
		fmt.Println("Open this URL in your browser to log in:")
		fmt.Println(url)
		fmt.Print("Enter OAuth token: ")
		token, err := readLine()
		if err != nil {
			return err
		}
		userData, err := c.OAuthLoginCallback(ctx, token)
		if err != nil {
			return err
		}
		return printJSON(redactUserData(userData))
	}

	email, err := prompt("Email: ")
	if err != nil {
		return err
	}
	password, err := promptPassword("Password: ")
	if err != nil {
		return err
	}

	userData, err := c.Login(ctx, email, password)
	if err != nil {
		return err
	}
	fmt.Println("Logged in successfully.")
	return printJSON(redactUserData(userData))
}

func accountLogout(ctx context.Context, c *ipc.Client) error {
	email, err := requireLoggedIn(ctx, c)
	if err != nil {
		return err
	}
	_, err = c.Logout(ctx, email)
	if err != nil {
		return err
	}
	fmt.Println("Logged out successfully.")
	return nil
}

func accountSignup(ctx context.Context, c *ipc.Client) error {
	if err := requireLoggedOut(ctx, c); err != nil {
		return err
	}

	email, err := prompt("Email: ")
	if err != nil {
		return err
	}
	password, err := promptPassword("Password: ")
	if err != nil {
		return err
	}
	confirm, err := promptPassword("Confirm password: ")
	if err != nil {
		return err
	}
	if password != confirm {
		return fmt.Errorf("passwords do not match")
	}

	_, resp, err := c.SignUp(ctx, email, password)
	if err != nil {
		return err
	}
	fmt.Println("Account created successfully.")

	fmt.Println("A confirmation code has been sent to your email.")
	code, err := prompt("Confirmation code: ")
	if err != nil {
		return err
	}
	if err := c.SignupEmailConfirmation(ctx, email, code); err != nil {
		return fmt.Errorf("email confirmation failed: %w", err)
	}
	fmt.Println("Email confirmed.")
	_ = resp
	return nil
}

func accountRecover(ctx context.Context, c *ipc.Client) error {
	if _, err := requireLoggedIn(ctx, c); err != nil {
		return err
	}

	email, err := prompt("Email: ")
	if err != nil {
		return err
	}

	if err := c.StartRecoveryByEmail(ctx, email); err != nil {
		return err
	}
	fmt.Println("A recovery code has been sent to your email.")

	code, err := prompt("Recovery code: ")
	if err != nil {
		return err
	}
	if err := c.ValidateEmailRecoveryCode(ctx, email, code); err != nil {
		return fmt.Errorf("invalid recovery code: %w", err)
	}

	newPassword, err := promptPassword("New password: ")
	if err != nil {
		return err
	}
	confirm, err := promptPassword("Confirm new password: ")
	if err != nil {
		return err
	}
	if newPassword != confirm {
		return fmt.Errorf("passwords do not match")
	}

	if err := c.CompleteRecoveryByEmail(ctx, email, newPassword, code); err != nil {
		return err
	}
	fmt.Println("Account recovered successfully. You can now log in with your new password.")
	return nil
}

func accountSetEmail(ctx context.Context, c *ipc.Client) error {
	if _, err := requireLoggedIn(ctx, c); err != nil {
		return err
	}

	newEmail, err := prompt("New email: ")
	if err != nil {
		return err
	}
	password, err := promptPassword("Password: ")
	if err != nil {
		return err
	}

	if err := c.StartChangeEmail(ctx, newEmail, password); err != nil {
		return err
	}
	fmt.Println("A confirmation code has been sent to your new email.")

	code, err := prompt("Confirmation code: ")
	if err != nil {
		return err
	}
	if err := c.CompleteChangeEmail(ctx, newEmail, password, code); err != nil {
		return err
	}
	fmt.Println("Email changed successfully.")
	return nil
}

func accountDataUsage(ctx context.Context, c *ipc.Client) error {
	info, err := c.DataCapInfo(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Enabled: %t\n", info.Enabled)
	if !info.Enabled {
		return nil
	}
	if info.Usage == nil {
		return fmt.Errorf("data usage info is unavailable")
	}
	bytesAllowed, _ := strconv.Atoi(info.Usage.BytesAllotted)
	BytesUsed, _ := strconv.Atoi(info.Usage.BytesUsed)
	resetTime := info.Usage.AllotmentEndTime

	fmt.Printf(
		"Data used: %.2f MB / %.2f MB (%.2f%%)\n",
		float64(BytesUsed)/1e6, float64(bytesAllowed)/1e6,
		100*float64(BytesUsed)/float64(bytesAllowed),
	)
	fmt.Printf("Resets at: %s\n", resetTime)
	return nil
}

func accountDevices(ctx context.Context, c *ipc.Client, cmd *DevicesCmd) error {
	if _, err := requireLoggedIn(ctx, c); err != nil {
		return err
	}

	switch {
	case cmd.Remove != "":
		resp, err := c.RemoveDevice(ctx, cmd.Remove)
		if err != nil {
			return err
		}
		fmt.Println("Device removed.")
		return printJSON(resp)
	default:
		devices, err := c.UserDevices(ctx)
		if err != nil {
			return err
		}
		return printJSON(devices)
	}
}

// redactedUserData is the subset of [account.UserData] safe to print; it omits
// the pro tokens and JWT.
type redactedUserData struct {
	ID             string `json:"id"`
	LegacyID       int64  `json:"legacyID"`
	Email          string `json:"email,omitempty"`
	EmailConfirmed bool   `json:"emailConfirmed"`
	Success        bool   `json:"success"`
}

func redactUserData(u *account.UserData) redactedUserData {
	return redactedUserData{
		ID:             u.GetId(),
		LegacyID:       u.GetLegacyID(),
		Email:          u.GetLegacyUserData().GetEmail(),
		EmailConfirmed: u.GetEmailConfirmed(),
		Success:        u.GetSuccess(),
	}
}

func prompt(label string) (string, error) {
	fmt.Print(label)
	return readLine()
}

// readLine reads a single line from stdin, trimming the trailing newline.
func readLine() (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("unexpected end of input")
	}
	return strings.TrimSpace(scanner.Text()), nil
}

// promptPassword prints a prompt and reads a password without echoing it.
func promptPassword(label string) (string, error) {
	fmt.Print(label)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // newline after hidden input
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(password), nil
}
