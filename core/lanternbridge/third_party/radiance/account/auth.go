package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/1Password/srp"
	"golang.org/x/crypto/pbkdf2"
	"google.golang.org/protobuf/proto"

	"github.com/getlantern/radiance/account/protos"
)

func (a *Client) fetchSalt(ctx context.Context, email string) (*protos.GetSaltResponse, error) {
	query := map[string]string{"email": email}
	resp, err := a.sendRequest(ctx, "GET", "/users/salt", query, nil, nil)
	if err != nil {
		return nil, err
	}
	var salt protos.GetSaltResponse
	if err := proto.Unmarshal(resp, &salt); err != nil {
		return nil, fmt.Errorf("unmarshaling salt response: %w", err)
	}
	return &salt, nil
}

// clientProof performs the SRP authentication flow to generate the client proof for the given email and password.
func (a *Client) clientProof(ctx context.Context, email, password string, salt []byte) ([]byte, error) {
	srpClient, err := newSRPClient(email, password, salt)
	if err != nil {
		return nil, err
	}

	A := srpClient.EphemeralPublic()
	data := &protos.PrepareRequest{
		Email: email,
		A:     A.Bytes(),
	}
	resp, err := a.sendRequest(ctx, "POST", "/users/prepare", nil, nil, data)
	if err != nil {
		return nil, err
	}

	var srpB protos.PrepareResponse
	if err := proto.Unmarshal(resp, &srpB); err != nil {
		return nil, fmt.Errorf("unmarshaling prepare response: %w", err)
	}
	B := big.NewInt(0).SetBytes(srpB.B)
	if err = srpClient.SetOthersPublic(B); err != nil {
		return nil, err
	}

	key, err := srpClient.Key()
	if err != nil || key == nil {
		return nil, fmt.Errorf("user_not_found error while generating Client key %w", err)
	}
	if !srpClient.GoodServerProof(salt, email, srpB.Proof) {
		return nil, fmt.Errorf("user_not_found checking server proof %w", err)
	}

	proof, err := srpClient.ClientProof()
	if err != nil {
		return nil, fmt.Errorf("user_not_found generating client proof %w", err)
	}
	return proof, nil
}

// getSalt retrieves the salt for the given email address or it's cached value.
func (a *Client) getSalt(ctx context.Context, email string) ([]byte, error) {
	if cached := a.getSaltCached(); cached != nil {
		return cached, nil
	}
	resp, err := a.fetchSalt(ctx, email)
	if err != nil {
		return nil, err
	}
	return resp.Salt, nil
}

const group = srp.RFC5054Group3072

func newSRPClient(email, password string, salt []byte) (*srp.SRP, error) {
	if len(salt) == 0 || len(password) == 0 || len(email) == 0 {
		return nil, errors.New("salt, password and email should not be empty")
	}

	encryptedKey, err := generateEncryptedKey(password, email, salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate encrypted key: %w", err)
	}

	return srp.NewSRPClient(srp.KnownGroups[group], encryptedKey, nil), nil
}

func generateEncryptedKey(password, email string, salt []byte) (*big.Int, error) {
	if len(salt) == 0 || len(password) == 0 || len(email) == 0 {
		return nil, errors.New("salt or password or email is empty")
	}
	combinedInput := password + email
	encryptedKey := pbkdf2.Key([]byte(combinedInput), salt, 4096, 32, sha256.New)
	encryptedKeyBigInt := big.NewInt(0).SetBytes(encryptedKey)
	return encryptedKeyBigInt, nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if n, err := rand.Read(salt); err != nil {
		return nil, err
	} else if n != 16 {
		return nil, errors.New("failed to generate 16 byte salt")
	}
	return salt, nil
}
