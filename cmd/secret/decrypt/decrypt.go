/*
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package decrypt

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"opendev.org/airship/airshipctl/pkg/environment"
	"opendev.org/airship/airshipctl/pkg/k8s/client"

	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/keys"
	"go.mozilla.org/sops/v3/keyservice"
	"go.mozilla.org/sops/v3/pgp"
)

var (
	keyOutputPrefix = "gpg-signing"
	keyOutputDir    = "/tmp/gpg/"
	gpgkeyFileName  = "gpg-key"
	gpgSecretName   = "gpg-encryption-key"
	ns              = "kube-system"
)

const (
	decryptLong = `	
Decrypts the provided secret yaml file using SOPS 
airshipctl secret decrypt --from-file <file-name> --to-file <file-name>
`
	decryptExample = `
airshipctl secret dncrypt --from-file /tmp/encrypted-secret.yaml --to-file /tmp/decrypted-secret.yaml
`
)

// NewGenerateCommand creates a new command for generating secret information
func NewDecryptCommand(rootSettings *environment.AirshipCTLSettings, factory client.Factory) *cobra.Command {
	var srcFile, dstFile string
	decryptCmd := &cobra.Command{
		Use:     "decrypt",
		Short:   "Decrypt a Kubernetes secret object using sops",
		Long:    decryptLong[1:],
		Example: decryptExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "running decrypt command")
			err := decryptSecret(rootSettings, factory, srcFile, dstFile)
			if err != nil {
				return fmt.Errorf("failed decrypting secrets: %s", err.Error())
			}
			fmt.Fprint(os.Stdout, "successfully decrypted secrets\n")
			return nil
		},
	}

	decryptCmd.Flags().StringVarP(&srcFile, "from-file", "f", "",
		"SOPS encrypted secret file")
	decryptCmd.Flags().StringVarP(&dstFile, "to-file", "t", "",
		"decrypted secret file")

	return decryptCmd
}

func decryptSecret(rootSettings *environment.AirshipCTLSettings, factory client.Factory, srcFile string, dstFile string) error {

	err := validateFiles(srcFile, dstFile)
	if err != nil {
		return err
	}
	kclient, err := factory(rootSettings)
	if err != nil {
		return err
	}

	priKeyFileName := fmt.Sprintf("%s%s.pri", keyOutputDir, gpgkeyFileName)
	//pubKeyFileName := fmt.Sprintf("/tmp/gpg/%s.pub", "docker-test")

	secret, err := kclient.ClientSet().CoreV1().Secrets(ns).Get(gpgSecretName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(priKeyFileName, secret.Data["pri_key"], 0644)
	if err != nil {
		return err
	}

	defer func() {
		os.Remove(priKeyFileName)
	}()

	gpgCmd := exec.Command("gpg", "--import", priKeyFileName)
	var out, errOut bytes.Buffer
	gpgCmd.Stdout = &out
	gpgCmd.Stderr = &errOut
	err = gpgCmd.Run()

	fmt.Println(err)
	fmt.Println("1. ", string(errOut.Bytes()))
	fmt.Println("2. ", string(out.Bytes()))

	keySvc := keyservice.NewLocalClient()
	tree, err := common.LoadEncryptedFileWithBugFixes(common.GenericDecryptOpts{
		Cipher:      aes.NewCipher(),
		InputStore:  common.DefaultStoreForPathOrFormat(srcFile, "yaml"),
		InputPath:   srcFile,
		KeyServices: []keyservice.KeyServiceClient{keySvc},
	})
	if err != nil {
		return err
	}

	_, err = common.DecryptTree(common.DecryptTreeOpts{
		Tree:        tree,
		KeyServices: []keyservice.KeyServiceClient{keySvc},
		Cipher:      aes.NewCipher(),
	})
	if err != nil {
		return err
	}

	dstStore := common.DefaultStoreForPath(dstFile)
	output, err := dstStore.EmitPlainFile(tree.Branches)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dstFile, output, 0644)
	if err != nil {
		return err
	}

	// TODO: Import encryption and decryption keys locally

	// TODO: Run encrypt from the sops

	// TODO: Add test cases
	return nil

}

// Config for generating keys.
type Config struct {
	packet.Config
	// Expiry is the duration that the generated key will be valid for.
	Expiry time.Duration
}

// Key represents an OpenPGP key.
type Key struct {
	openpgp.Entity
}

// Values from https://tools.ietf.org/html/rfc4880#section-9
const (
	md5       = 1
	sha1      = 2
	ripemd160 = 3
	sha256    = 8
	sha384    = 9
	sha512    = 10
	sha224    = 11
)

func CreateKey(name, comment, email string, config *Config) (*Key, error) {
	// Create the key
	key, err := openpgp.NewEntity(name, comment, email, &config.Config)
	if err != nil {
		return nil, err
	}

	// Set expiry and algorithms. Self-sign the identity.
	dur := uint32(config.Expiry.Seconds())
	for _, id := range key.Identities {
		id.SelfSignature.KeyLifetimeSecs = &dur

		id.SelfSignature.PreferredSymmetric = []uint8{
			uint8(packet.CipherAES256),
			uint8(packet.CipherAES192),
			uint8(packet.CipherAES128),
			uint8(packet.CipherCAST5),
			uint8(packet.Cipher3DES),
		}

		id.SelfSignature.PreferredHash = []uint8{
			sha256,
			sha1,
			sha384,
			sha512,
			sha224,
		}

		id.SelfSignature.PreferredCompression = []uint8{
			uint8(packet.CompressionZLIB),
			uint8(packet.CompressionZIP),
		}

		err := id.SelfSignature.SignUserId(id.UserId.Id, key.PrimaryKey, key.PrivateKey, &config.Config)
		if err != nil {
			return nil, err
		}
	}

	// Self-sign the Subkeys
	for _, subkey := range key.Subkeys {
		subkey.Sig.KeyLifetimeSecs = &dur
		err := subkey.Sig.SignKey(subkey.PublicKey, key.PrivateKey, &config.Config)
		if err != nil {
			return nil, err
		}
	}

	r := Key{*key}
	return &r, nil
}

// Armor returns the public part of a key in armored format.
func (key *Key) Armor() (string, error) {
	buf := new(bytes.Buffer)
	armor, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", err
	}
	key.Serialize(armor)
	armor.Close()

	return buf.String(), nil
}

// ArmorPrivate returns the private part of a key in armored format.
//
// Note: if you want to protect the string against varous low-level attacks,
// you should look at https://github.com/stouset/go.secrets and
// https://github.com/worr/secstring and then re-implement this function.
func (key *Key) ArmorPrivate(config *Config) (string, error) {
	buf := new(bytes.Buffer)
	armor, err := armor.Encode(buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return "", err
	}
	c := config.Config
	key.SerializePrivate(armor, &c)
	armor.Close()

	return buf.String(), nil
}

// A keyring is simply one (or more) keys in binary format.
func (key *Key) Keyring() []byte {
	buf := new(bytes.Buffer)
	key.Serialize(buf)
	return buf.Bytes()
}

// A secring is simply one (or more) keys in binary format.
func (key *Key) Secring(config *Config) []byte {
	buf := new(bytes.Buffer)
	c := config.Config
	key.SerializePrivate(buf, &c)
	return buf.Bytes()
}

func getKeyGroup(priKeyBytes []byte) ([]sops.KeyGroup, error) {
	b := bytes.NewReader(priKeyBytes)
	bufferedReader := bufio.NewReader(b)
	entities, err := openpgp.ReadArmoredKeyRing(bufferedReader)
	if err != nil {
		return nil, err
	}
	fingerprint := fmt.Sprintf("%X", entities[0].PrivateKey.Fingerprint[:])
	var pgpKeys []keys.MasterKey
	// TODO: Investigate how to retrieve this finger print
	for _, k := range pgp.MasterKeysFromFingerprintString(fingerprint) {
		pgpKeys = append(pgpKeys, k)
	}

	var group sops.KeyGroup
	group = append(group, pgpKeys...)
	return []sops.KeyGroup{group}, nil
}

func ensureNoMetadata(branch sops.TreeBranch) error {
	for _, b := range branch {
		if b.Key == "sops" {
			return fmt.Errorf("file already encrypted")
		}
	}
	return nil
}

func validateFiles(srcFile string, dstFile string) error {
	if !(len(srcFile) == 0) && !(len(dstFile) == 0) {
		if _, err := os.Stat(srcFile); os.IsNotExist(err) {
			return fmt.Errorf(err.Error())
		}
		if _, err := os.Stat(dstFile); !os.IsNotExist(err) {
			fmt.Fprint(os.Stdout, "Warning: Overriding "+dstFile+"\n")
		}
	} else {
		return fmt.Errorf("Expecting from-file and to-file flags")
	}

	return nil
}
