package toolbox

import (
	"context"
	"fmt"

	"github.com/godaddy/asherah/go/appencryption"
	"github.com/godaddy/asherah/go/appencryption/pkg/crypto/aead"
	"github.com/godaddy/asherah/go/appencryption/pkg/kms"
	"github.com/godaddy/asherah/go/appencryption/pkg/persistence"
	"github.com/opentracing/opentracing-go"
)

// Decrypt a data blob using asherah.
// The jobID is used to find the appropriate asherah session to use.
func (t *Toolbox) Decrypt(ctx context.Context, jobID string, decryptionRecord appencryption.DataRowRecord) ([]byte, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "DecryptData")
	span.LogKV("dataSizeBytes", len(decryptionRecord.Data))
	defer span.Finish()

	session, err := t.GetAsherahSession(ctx, jobID)
	if err != nil {
		span.LogKV("error", err)
		return nil, fmt.Errorf("error getting asherah session: %w", err)
	}
	out, err := session.Decrypt(decryptionRecord)
	if err != nil {
		span.LogKV("error", err)
		return nil, err
	}

	return out, nil
}

// Encrypt a data blob using asherah
// The jobID is used to find the appropriate asherah session to use.
func (t *Toolbox) Encrypt(ctx context.Context, jobID string, data []byte) (*appencryption.DataRowRecord, error) {
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "EncryptData")
	span.LogKV("dataSizeBytes", len(data))
	defer span.Finish()

	session, err := t.GetAsherahSession(ctx, jobID)
	if err != nil {
		span.LogKV("error", err)
		return nil, fmt.Errorf("error getting asherah session: %w", err)
	}
	out, err := session.Encrypt(data)
	if err != nil {
		span.LogKV("error", err)
		return nil, err
	}

	return out, nil
}

// GetAsherahSession Get the current asherah session of this tookbox, or create one if it doesn't exist
func (t *Toolbox) GetAsherahSession(ctx context.Context, jobID string) (*appencryption.Session, error) {
	// Check if we already have a session
	if asherahSession, ok := t.AsherahSession[jobID]; ok {
		return asherahSession, nil
	}

	// Close the old sessions
	err := t.CloseAsherahSessions(ctx)
	if err != nil {
		return nil, err
	}

	session, err := t.getAsherahSession(ctx, jobID)
	if err != nil {
		return nil, err
	}
	t.AsherahSession[jobID] = session

	return t.AsherahSession[jobID], nil
}

// CloseAsherahSessions Closes any asherah sessions we have open
func (t *Toolbox) CloseAsherahSessions(ctx context.Context) error {
	span, ctx := opentracing.StartSpanFromContext(ctx, "CloseAsherahSessions")
	defer span.Finish()
	for jobID, ashrahSession := range t.AsherahSession {
		err := ashrahSession.Close()
		if err != nil {
			return fmt.Errorf("error closing asherah session: %w", err)
		}
		delete(t.AsherahSession, jobID)
	}
	return nil
}

// getAsherahSession Performs all the setup for getting an asherah session
func (t *Toolbox) getAsherahSession(ctx context.Context, sessionID string) (*appencryption.Session, error) {
	if t.AWSSession == nil {
		return nil, ErrNoAWSSession
	}

	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "SetUpAsherahSession")
	defer span.Finish()

	// Build session factory if we haven't already
	if t.AsherahSessionFactory == nil {
		err := t.getAsherahSessionFactory(ctx)
		if err != nil {
			return nil, fmt.Errorf("error getting session factory: %w", err)
		}
	}

	session, err := t.AsherahSessionFactory.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("error creating session: %w", err)
	}

	return session, nil
}

// Build the asherah session factory
func (t *Toolbox) getAsherahSessionFactory(ctx context.Context) error {
	// Build the Metastore
	var span opentracing.Span
	span, ctx = opentracing.StartSpanFromContext(ctx, "SetUpAsherahSessionFactory")
	defer span.Finish()

	// Create metastore from AWS session
	metastore := persistence.NewDynamoDBMetastore(
		t.AWSSession,
		persistence.WithDynamoDBRegionSuffix(true),
		persistence.WithTableName(t.AsherahDBTableName),
	)

	// Create a map of region and ARN pairs that will all be used when creating a System Key
	// First if the regionARN is blank, look it up in SSM
	if t.AsherahRegionARN == "" {
		// Look up the ARN in aws SSM (parameter store)
		kmsKey, err := t.GetFromParameterStore(ctx, asherahKMSKeyParameterName, false)
		if err != nil {
			return fmt.Errorf("error getting ARN of KMS Key: %w", err)
		}
		t.AsherahRegionARN = *kmsKey.Value
	}
	regionArnMap := map[string]string{
		t.AsherahRegion: t.AsherahRegionARN,
	}

	// Use AES/GCM encryption
	crypto := aead.NewAES256GCM()
	// Build the Key Management Service using the region dictionary and your preferred (usually current) region
	keyManagementService, err := kms.NewAWS(crypto, *t.AWSSession.Config.Region, regionArnMap)
	if err != nil {
		return fmt.Errorf("error creating aws key management service: %w", err)
	}

	// Create a session factory
	sessionFactory := appencryption.NewSessionFactory(
		&appencryption.Config{
			Service: "ThreatAPI",
			Product: "Threat Research",
			Policy:  appencryption.NewCryptoPolicy(),
		},
		metastore,
		keyManagementService,
		crypto,
	)

	t.AsherahSessionFactory = sessionFactory
	return nil
}
