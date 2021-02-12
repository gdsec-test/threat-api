package toolbox

import (
	"context"
	"reflect"
	"testing"
)

func TestEncrypt(t *testing.T) {
	toolbox := GetToolbox()
	ctx := context.Background()
	getTestingAWSSession(ctx, toolbox)

	testData := []byte("Test Data")

	// Test encryption
	encryptedData, err := toolbox.Encrypt(ctx, "TestJob", testData)
	if err != nil {
		t.Errorf("error encrypting: %w", err)
		return
	}

	decryptedData, err := toolbox.Decrypt(ctx, "TestJob", *encryptedData)
	if err != nil {
		t.Errorf("error decrypting: %w", err)
		return
	}
	if !reflect.DeepEqual(decryptedData, testData) {
		t.Errorf("Did not get expected data (%s), got: %s", string(testData), string(decryptedData))
	}
}
