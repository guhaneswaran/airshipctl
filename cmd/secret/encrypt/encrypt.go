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

package encrypt

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"opendev.org/airship/airshipctl/pkg/environment"
	"opendev.org/airship/airshipctl/pkg/k8s/client"

	"github.com/spf13/cobra"
	"go.mozilla.org/sops/v3/aes"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/keys"
	"go.mozilla.org/sops/v3/keyservice"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"go.mozilla.org/sops/v3"
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
	encryptLong = `	
Encrypts the provided secret yaml file using SOPS 
airshipctl secret encrypt --from-file <file-name> --to-file <file-name>
`
	encryptExample = `
airshipctl secret encrypt --from-file /tmp/unencrypted-secret.yaml --to-file /tmp/encrypted-secret.yaml
`
)

// NewEncryptCommand creates a new command for generating secret information
func NewEncryptCommand(rootSettings *environment.AirshipCTLSettings, factory client.Factory) *cobra.Command {
	var srcFile, dstFile string
	encryptCmd := &cobra.Command{
		Use:     "encrypt",
		Short:   "Encrypt a Kubernetes secret object using sops",
		Long:    encryptLong[1:],
		Example: encryptExample,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "running encrypt command")
			err := encryptSecret(rootSettings, factory, srcFile, dstFile)
			if err != nil {
				return fmt.Errorf("failed encrypting secrets: %s", err.Error())
			}
			fmt.Fprint(os.Stdout, "successfully encrypted secrets\n")
			return nil
		},
	}

	encryptCmd.Flags().StringVarP(&srcFile, "from-file", "f", "",
		"(Unencrypted) Source secret file")
	encryptCmd.Flags().StringVarP(&dstFile, "to-file", "t", "",
		"SOPS encrypted secret file")

	return encryptCmd
}

func encryptSecret(rootSettings *environment.AirshipCTLSettings, factory client.Factory, srcFile string, dstFile string) error {

	err := validateFiles(srcFile, dstFile)
	if err != nil {
		return err
	}

	kclient, err := factory(rootSettings)
	priKeyFileName := fmt.Sprintf("%s/%s.pri", keyOutputDir, gpgkeyFileName)
	//pubKeyFileName := fmt.Sprintf("/tmp/gpg/%s.pub", "docker-test")

	var pubKeyBytes, privKeyBytes []byte
	secret, err := kclient.ClientSet().CoreV1().Secrets(ns).Get(gpgSecretName, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	} else if errors.IsNotFound(err) {
		// generate key pair and save it as secret
		pubKeyBytes, privKeyBytes, err = generateKeyPair(gpgkeyFileName, keyOutputDir)
		if err != nil {
			return err
		}
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: gpgSecretName,
			},
			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			Data: map[string][]byte{
				"pub_key": pubKeyBytes,
				"pri_key": privKeyBytes,
			},
		}
		_, err = kclient.ClientSet().CoreV1().Secrets(ns).Create(secret)
		if err != nil {
			return err
		}
	}

	err = writeFile(priKeyFileName, secret.Data["pri_key"])
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

	groups, err := getKeyGroup(secret.Data["pub_key"])
	if err != nil {
		return err
	}

	store := common.DefaultStoreForPath(srcFile)

	fileBytes, err := ioutil.ReadFile(srcFile)
	if err != nil {
		return fmt.Errorf("error reading file: %s", err)
	}

	branches, err := store.LoadPlainFile(fileBytes)
	if err != nil {
		return fmt.Errorf("error unmarshalling file: %s", err)
	}

	if err := ensureNoMetadata(branches[0]); err != nil {
		return err
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:      groups,
			Version:        "3.6.0",
			EncryptedRegex: "^data",
		},
		FilePath: srcFile,
	}

	keySvc := keyservice.NewLocalClient()
	dataKey, errors := tree.GenerateDataKeyWithKeyServices([]keyservice.KeyServiceClient{keySvc})
	if len(errors) > 0 {
		return fmt.Errorf("%s", errors)
	}
	err = common.EncryptTree(common.EncryptTreeOpts{
		Tree:    &tree,
		Cipher:  aes.NewCipher(),
		DataKey: dataKey,
	})
	if err != nil {
		return err
	}

	dstStore := common.DefaultStoreForPath(dstFile)
	output, err := dstStore.EmitEncryptedFile(tree)
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

func generateKeyPair(name string, dstDir string) ([]byte, []byte, error) {
	key, err := CreateKey(name, name, fmt.Sprintf("%s@cluster.local", name), &Config{})
	if err != nil {
		return nil, nil, err
	}

	priKeyFilename := fmt.Sprintf("%s/%s.pri", dstDir, name)
	privateKey, err := key.ArmorPrivate(&Config{})
	if err != nil {
		return nil, nil, err
	}

	_, err = os.Create(priKeyFilename)
	if err != nil {
		return nil, nil, err
	}
	err = ioutil.WriteFile(priKeyFilename, []byte(privateKey), 0644)
	if err != nil {
		return nil, nil, err
	}

	pubKeyFilename := fmt.Sprintf("%s/%s.pub", dstDir, name)
	publicKey, err := key.Armor()
	if err != nil {
		return nil, nil, err
	}
	_, err = os.Create(pubKeyFilename)
	if err != nil {
		return nil, nil, err
	}
	err = ioutil.WriteFile(pubKeyFilename, []byte(publicKey), 0644)
	if err != nil {
		return nil, nil, err
	}

	return []byte(publicKey), []byte(privateKey), nil
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

// CreateKey if not present
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

// Keyring - A keyring is simply one (or more) keys in binary format.
func (key *Key) Keyring() []byte {
	buf := new(bytes.Buffer)
	key.Serialize(buf)
	return buf.Bytes()
}

// Secring  A secring is simply one (or more) keys in binary format.
func (key *Key) Secring(config *Config) []byte {
	buf := new(bytes.Buffer)
	c := config.Config
	key.SerializePrivate(buf, &c)
	return buf.Bytes()
}

func getKeyGroup(publicKeyBytes []byte) ([]sops.KeyGroup, error) {
	b := bytes.NewReader(publicKeyBytes)
	bufferedReader := bufio.NewReader(b)
	entities, err := openpgp.ReadArmoredKeyRing(bufferedReader)
	if err != nil {
		return nil, err
	}
	fingerprint := fmt.Sprintf("%X", entities[0].PrimaryKey.Fingerprint[:])
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

func writeFile(path string, content []byte) error {
	return ioutil.WriteFile(path, content, 0644)
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
