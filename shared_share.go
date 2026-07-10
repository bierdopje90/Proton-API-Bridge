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

// SharedShareInfo describes one shared-with-me share.
type SharedShareInfo struct {
	ShareID string
	LinkID  string
	Name    string // decrypted name of the share's root folder, "" when undecryptable
	Creator string // owner email address
	ModTime int64  // last modification of the share, Unix seconds
}

// ListSharedWithMeShares enumerates the shares other users have shared with
// this account, decrypting each share's root folder name. Shares that fail to
// bootstrap or unlock are skipped with a warning rather than failing the whole
// listing.
func (protonDrive *ProtonDrive) ListSharedWithMeShares(ctx context.Context) ([]SharedShareInfo, error) {
	logger := protonDrive.Config.GetLogger()

	links, err := protonDrive.c.ListSharedWithMeLinks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list shared-with-me items: %w", err)
	}

	infos := make([]SharedShareInfo, 0, len(links))
	for i := range links {
		share, err := getShareByID(ctx, protonDrive.c, links[i].ShareID)
		if err != nil {
			logger.Warnf("skipping shared-with-me share %s: failed to get bootstrap: %v", links[i].ShareID, err)
			continue
		}
		if share.State != proton.ShareStateActive {
			logger.Warnf("skipping shared-with-me share %s: not active (state %d)", share.ShareID, share.State)
			continue
		}

		info := SharedShareInfo{
			ShareID: share.ShareID,
			LinkID:  share.LinkID,
			Creator: share.Creator,
			ModTime: share.ModifyTime,
		}

		// Best effort on the display name: a share root's name is encrypted
		// like any other link, but the share keyring stands in for the parent
		// node keyring since the true parent lives in the owner's tree.
		shareKR, err := unlockShareKeyRing(protonDrive.Config, share, protonDrive.addrKRs[share.AddressID])
		if err != nil {
			logger.Warnf("cannot unlock shared-with-me share %s, name left empty: %v", share.ShareID, err)
			infos = append(infos, info)
			continue
		}

		rootLink, err := protonDrive.c.GetLink(ctx, share.ShareID, share.LinkID)
		if err != nil {
			logger.Warnf("cannot get root link of shared-with-me share %s, name left empty: %v", share.ShareID, err)
			infos = append(infos, info)
			continue
		}

		signatureVerificationKR, err := protonDrive.getSignatureVerificationKeyring([]string{rootLink.NameSignatureEmail, rootLink.SignatureEmail}, shareKR)
		if err == nil {
			if name, err := rootLink.GetName(shareKR, signatureVerificationKR); err == nil {
				info.Name = name
			} else {
				logger.Warnf("cannot decrypt name of shared-with-me share %s: %v", share.ShareID, err)
			}
		}

		infos = append(infos, info)
	}

	return infos, nil
}

// NewDriveForShare returns a ProtonDrive rooted at the given share, reusing
// this instance's session, user/address keyrings and configuration. No
// additional login is performed. The returned instance must not be used to
// Logout, as that would invalidate the shared session.
func (protonDrive *ProtonDrive) NewDriveForShare(ctx context.Context, shareID string) (*ProtonDrive, error) {
	share, err := getShareByID(ctx, protonDrive.c, shareID)
	if err != nil {
		return nil, fmt.Errorf("failed to get share %s: %w", shareID, err)
	}
	if share.State != proton.ShareStateActive {
		return nil, fmt.Errorf("share %s is not active (state %d)", shareID, share.State)
	}

	addrKR := protonDrive.addrKRs[share.AddressID]
	shareKR, err := unlockShareKeyRing(protonDrive.Config, share, addrKR)
	if err != nil {
		return nil, err
	}

	rootLink, err := protonDrive.c.GetLink(ctx, share.ShareID, share.LinkID)
	if err != nil {
		return nil, fmt.Errorf("failed to get root link of share %s: %w", shareID, err)
	}

	signatureAddress := protonDrive.signatureAddress
	for email, addr := range protonDrive.addrData {
		if addr.ID == share.AddressID {
			signatureAddress = email
		}
	}

	return &ProtonDrive{
		MainShare: share,
		RootLink:  &rootLink,

		MainShareKR:   shareKR,
		DefaultAddrKR: addrKR,

		Config: protonDrive.Config,

		c:                protonDrive.c,
		m:                protonDrive.m,
		userKR:           protonDrive.userKR,
		addrKRs:          protonDrive.addrKRs,
		addrData:         protonDrive.addrData,
		signatureAddress: signatureAddress,

		cache: newCache(protonDrive.Config.EnableCaching, protonDrive.Config.GetLogger()),
		// concurrency limits are global to the session, so the semaphores are shared
		blockUploadSemaphore: protonDrive.blockUploadSemaphore,
		blockCryptoSemaphore: protonDrive.blockCryptoSemaphore,

		// own map: sharing the parent's would require sharing its mutex too
		pubKeyCache: make(map[string]*crypto.KeyRing),
	}, nil
}

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
