package proton_api_bridge

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/rclone/Proton-API-Bridge/common"
	"github.com/rclone/go-proton-api"
)

/*
Shared-with-me support.

A share another user has shared with this account lives in the OWNER's volume,
so it is invisible to the volume enumeration used for the main share. It is
still a regular share: GET /drive/shares/{shareID} returns a bootstrap whose
membership carries the share passphrase session key encrypted to OUR address
key. Once the share keyring is unlocked, all link/block operations work
unchanged against the owner's volume.
*/

// getSharedShare resolves config.SharedShareID ("auto" or an explicit share ID)
// to a share bootstrap.
func getSharedShare(ctx context.Context, config *common.Config, c *proton.Client) (*proton.Share, error) {
	shareID := config.SharedShareID

	if strings.EqualFold(shareID, "auto") {
		links, err := c.ListSharedWithMeLinks(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list shared-with-me items: %w", err)
		}

		switch len(links) {
		case 0:
			return nil, fmt.Errorf("share_id is set to auto but no one has shared a folder with this account")
		case 1:
			shareID = links[0].ShareID
		default:
			ids := make([]string, len(links))
			for i := range links {
				ids[i] = links[i].ShareID
			}
			return nil, fmt.Errorf("share_id is set to auto but %d items are shared with this account, set share_id explicitly to one of: %s", len(links), strings.Join(ids, ", "))
		}
	}

	share, err := getShareByID(ctx, c, shareID)
	if err != nil {
		return nil, fmt.Errorf("failed to get share %s: %w", shareID, err)
	}

	if share.State != proton.ShareStateActive {
		return nil, fmt.Errorf("share %s is not active (state %d)", shareID, share.State)
	}

	return share, nil
}

// unlockShareKeyRing unlocks a share keyring for a share we are a member of
// rather than the owner. The share passphrase PGP message may carry a key
// packet addressed to the owner's key; our session key arrives in the
// membership's KeyPacket, which is spliced onto the passphrase data packet.
//
// The passphrase signature is made by the share creator, not by us; access
// control is enforced server-side and the creator's link signatures are
// verified separately via getSignatureVerificationKeyring, so it is not
// verified here.
func unlockShareKeyRing(config *common.Config, share *proton.Share, addrKR *crypto.KeyRing) (*crypto.KeyRing, error) {
	if addrKR == nil {
		return nil, fmt.Errorf("no address keyring for share member address %s", share.AddressID)
	}

	logger := config.GetLogger()

	var passphrase *crypto.PlainMessage

	// Try the embedded key packet first - it may already target our address key.
	if enc, err := crypto.NewPGPMessageFromArmored(share.Passphrase); err == nil {
		if dec, err := addrKR.Decrypt(enc, nil, 0); err == nil {
			passphrase = dec
		}
	}

	// Fall back to splicing each membership key packet onto the passphrase data packet.
	if passphrase == nil {
		split, err := crypto.NewPGPSplitMessageFromArmored(share.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to parse share passphrase message: %w", err)
		}

		for i := range share.Memberships {
			keyPacket, err := base64.StdEncoding.DecodeString(share.Memberships[i].KeyPacket)
			if err != nil {
				logger.Warnf("skipping malformed membership key packet %d of share %s: %v", i, share.ShareID, err)
				continue
			}

			spliced := crypto.NewPGPSplitMessage(keyPacket, split.GetBinaryDataPacket()).GetPGPMessage()
			if dec, err := addrKR.Decrypt(spliced, nil, 0); err == nil {
				passphrase = dec
				break
			}
		}
	}

	if passphrase == nil {
		return nil, fmt.Errorf("could not decrypt passphrase of share %s with any of our address keys (%d memberships tried)", share.ShareID, len(share.Memberships))
	}

	lockedKey, err := crypto.NewKeyFromArmored(share.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse share key: %w", err)
	}

	unlockedKey, err := lockedKey.Unlock(passphrase.GetBinary())
	if err != nil {
		return nil, fmt.Errorf("failed to unlock share key: %w", err)
	}

	return crypto.NewKeyRing(unlockedKey)
}
