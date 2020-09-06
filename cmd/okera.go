package cmd

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/minio/minio/cmd/logger"
	"github.com/minio/minio/pkg/auth"
	"github.com/minio/minio/pkg/env"
	iampolicy "github.com/minio/minio/pkg/iam/policy"

	"github.com/okera/gokera"
	"github.com/okera/gokera/gen-go/okerarecordservice"
)

const (
	envOkeraPlannerHost = "OKERA_PLANNER_HOST"
	envOkeraPlannerPort = "OKERA_PLANNER_PORT"
	envOkeraSystemToken = "OKERA_SYSTEM_TOKEN"
)

var (
	trailingSlashRegex = regexp.MustCompile("/+$")
)

type okeraIAMStore struct {
	// Protect assignment to objAPI
	sync.RWMutex

	ctx         context.Context
	plannerHost string
	plannerPort int
	systemToken string
}

func newOkeraIAMStore(ctx context.Context) (*okeraIAMStore, error) {
	plannerHost := env.Get(envOkeraPlannerHost, "")
	if plannerHost == "" {
		return nil, fmt.Errorf("%s was not set", envOkeraPlannerHost)
	}

	var err error
	plannerPort := 0
	plannerPortStr := env.Get(envOkeraPlannerPort, "")
	if plannerPortStr == "" {
		return nil, fmt.Errorf("%s was not set", envOkeraPlannerPort)
	}
	if plannerPort, err = strconv.Atoi(plannerPortStr); err != nil {
		return nil, fmt.Errorf("Failed to parse value in '%s ('%s') as an integer", envOkeraPlannerPort, plannerPortStr)
	}

	systemToken := env.Get(envOkeraSystemToken, "")
	if systemToken == "" {
		return nil, fmt.Errorf("%s was not set", envOkeraSystemToken)
	}

	store := &okeraIAMStore{
		ctx:         ctx,
		plannerHost: plannerHost,
		plannerPort: plannerPort,
		systemToken: systemToken,
	}

	return store, nil
}

// TODO: this should be changed to only use the system token eventually and then
// this should be switched to implementing a planner connection pool to avoid
// creating a new connection every time.
func (s *okeraIAMStore) plannerConnection(token string) (*gokera.Connection, error) {
	env := &gokera.Environment{
		Username: token,
	}

	conn, err := env.CreateConnection(s.plannerHost, s.plannerPort)
	if err != nil {
		return nil, err
	}

	return conn, err
}

func (s *okeraIAMStore) getUserCredentials(user string) (auth.Credentials, error) {
	var creds auth.Credentials

	// TODO: need to properly handle how we get a token from a user,
	// which might change how we connect to the planner
	conn, err := s.plannerConnection(user)
	if err != nil {
		return creds, fmt.Errorf("Error connecting to planner: %w", err)
	}

	defer conn.Close()

	_, err = conn.GetServerVersion()
	if err != nil {
		return creds, fmt.Errorf("Error authenticating credentials: %w", err)
	}

	creds, err = auth.CreateCredentials(user, "okera_access")
	if err != nil {
		return creds, fmt.Errorf("Error creating credentials: %w", err)
	}

	// TODO: right now we set no expiration the credentials, but when
	// we start using real tokens from the backend, we will need to
	// set the expiry

	return creds, nil
}

func actionToOkeraOp(action iampolicy.Action) okerarecordservice.TListFilesOp {
	switch action {
	case iampolicy.AbortMultipartUploadAction:
	case iampolicy.BypassGovernanceRetentionAction:
	case iampolicy.CreateBucketAction:
		{
			return okerarecordservice.TListFilesOp_WRITE
		}
	case iampolicy.DeleteBucketAction:
	case iampolicy.DeleteBucketPolicyAction:
	case iampolicy.DeleteObjectAction:
	case iampolicy.DeleteObjectTaggingAction:
	case iampolicy.DeleteObjectVersionAction:
	case iampolicy.DeleteObjectVersionTaggingAction:
	case iampolicy.ForceDeleteBucketAction:
		{
			return okerarecordservice.TListFilesOp_DELETE
		}
	case iampolicy.GetBucketEncryptionAction:
	case iampolicy.GetBucketLifecycleAction:
	case iampolicy.GetBucketLocationAction:
	case iampolicy.GetBucketNotificationAction:
	case iampolicy.GetBucketObjectLockConfigurationAction:
	case iampolicy.GetBucketPolicyAction:
	case iampolicy.GetBucketTaggingAction:
	case iampolicy.GetBucketVersioningAction:
	case iampolicy.GetObjectAction:
	case iampolicy.GetObjectLegalHoldAction:
	case iampolicy.GetObjectRetentionAction:
	case iampolicy.GetObjectTaggingAction:
	case iampolicy.GetObjectVersionAction:
	case iampolicy.GetObjectVersionForReplicationAction:
	case iampolicy.GetObjectVersionTaggingAction:
	case iampolicy.GetReplicationConfigurationAction:
	case iampolicy.HeadBucketAction:
		{
			return okerarecordservice.TListFilesOp_READ
		}
	case iampolicy.ListAllMyBucketsAction:
	case iampolicy.ListBucketAction:
	case iampolicy.ListBucketMultipartUploadsAction:
	case iampolicy.ListBucketVersionsAction:
	case iampolicy.ListenBucketNotificationAction:
	case iampolicy.ListenNotificationAction:
	case iampolicy.ListMultipartUploadPartsAction:
		{
			return okerarecordservice.TListFilesOp_LIST
		}
	case iampolicy.PutBucketEncryptionAction:
	case iampolicy.PutBucketLifecycleAction:
	case iampolicy.PutBucketNotificationAction:
	case iampolicy.PutBucketObjectLockConfigurationAction:
	case iampolicy.PutBucketPolicyAction:
	case iampolicy.PutBucketTaggingAction:
	case iampolicy.PutBucketVersioningAction:
	case iampolicy.PutObjectAction:
	case iampolicy.PutObjectLegalHoldAction:
	case iampolicy.PutObjectRetentionAction:
	case iampolicy.PutObjectTaggingAction:
	case iampolicy.PutObjectVersionTaggingAction:
	case iampolicy.PutReplicationConfigurationAction:
	case iampolicy.ReplicateDeleteAction:
	case iampolicy.ReplicateObjectAction:
	case iampolicy.ReplicateTagsAction:
		{
			return okerarecordservice.TListFilesOp_WRITE
		}
	}
	return okerarecordservice.TListFilesOp_LIST
}

// IsAllowed - checks given policy args is allowed to continue the Rest API.
// TODO: we should add an in-memory cache that stores the policy decision for
// a given set of inputs, to avoid the RPC.
func (s *okeraIAMStore) IsAllowed(args iampolicy.Args) (bool, error) {
	// We always connect to the planner with the system token here, as we
	// are just going to check authorization for the user
	conn, err := s.plannerConnection(s.systemToken)
	if err != nil {
		return false, fmt.Errorf("Error connecting to planner: %w", err)
	}

	defer conn.Close()

	_, err = conn.GetServerVersion()
	if err != nil {
		return false, fmt.Errorf("Error authenticating credentials: %w", err)
	}

	prefix := ""
	if args.ObjectName != "" {
		prefix = args.ObjectName
	} else if prefixVal, ok := args.ConditionValues["prefix"]; ok && len(prefixVal) > 0 {
		prefix = prefixVal[0]
	}

	objPath := fmt.Sprintf("s3://%s/%s", args.BucketName, prefix)

	objPath = trailingSlashRegex.ReplaceAllLiteralString(objPath, "/")

	// TODO: when AuthorizeOnly is set, the backend ignores the Op
	// today. This should be fixed and it should check the specific
	// action we want to take. It's OK from a security perspective right
	// now since the backend verifies there is ALL on the URI (which
	// is the only possible URI grant)
	op := actionToOkeraOp(args.Action)
	authorizeOnly := true

	var params gokera.ListFilesParams = gokera.ListFilesParams{
		Op:             op,
		Object:         &objPath,
		RequestingUser: &args.AccountName,
		AuthorizeOnly:  &authorizeOnly,
	}

	fmt.Printf("IsAllowed: %s -- %s -- %s -- %s\n", args.AccountName, objPath, args.Action, op)

	// We don't care what the response itself is, as long as it is not
	// an error
	_, err = conn.ListFiles(params)
	if err != nil {
		return false, fmt.Errorf("Error checking authorization for '%s': %w", args.Action, err)
	}

	return true, nil
}

func (s *okeraIAMStore) lock() {
	s.Lock()
}

func (s *okeraIAMStore) unlock() {
	s.Unlock()
}

func (s *okeraIAMStore) rlock() {
	s.RLock()
}

func (s *okeraIAMStore) runlock() {
	s.RUnlock()
}

func (s *okeraIAMStore) migrateBackendFormat(context.Context) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) loadPolicyDoc(policy string, m map[string]iampolicy.Policy) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) loadPolicyDocs(ctx context.Context, m map[string]iampolicy.Policy) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) loadUser(user string, userType IAMUserType, m map[string]auth.Credentials) error {
	creds, err := s.getUserCredentials(user)
	if err != nil {
		return err
	}

	m[user] = creds
	return nil
}

func (s *okeraIAMStore) loadUsers(ctx context.Context, userType IAMUserType, m map[string]auth.Credentials) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) loadGroup(group string, m map[string]GroupInfo) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) loadGroups(ctx context.Context, m map[string]GroupInfo) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) loadMappedPolicy(name string, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) loadMappedPolicies(ctx context.Context, userType IAMUserType, isGroup bool, m map[string]MappedPolicy) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) expireAll(ctx context.Context, sys *IAMSys) error {
	// purge any expired entries which became expired now.s
	for k, v := range sys.iamUsersMap {
		if v.IsExpired() {
			delete(sys.iamUsersMap, k)
			delete(sys.iamUserPolicyMap, k)
		}
	}

	return nil
}

func (s *okeraIAMStore) loadAll(ctx context.Context, sys *IAMSys) error {
	return s.expireAll(ctx, sys)
}

func (s *okeraIAMStore) saveIAMConfig(item interface{}, path string) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) loadIAMConfig(item interface{}, path string) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) deleteIAMConfig(path string) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) savePolicyDoc(policyName string, p iampolicy.Policy) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) saveMappedPolicy(name string, userType IAMUserType, isGroup bool, mp MappedPolicy) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) saveUserIdentity(name string, userType IAMUserType, u UserIdentity) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) saveGroupInfo(group string, gi GroupInfo) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) deletePolicyDoc(policyName string) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) deleteMappedPolicy(name string, userType IAMUserType, isGroup bool) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) deleteUserIdentity(name string, userType IAMUserType) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) deleteGroupInfo(name string) error {
	// NYI
	return nil
}

func (s *okeraIAMStore) watch(ctx context.Context, sys *IAMSys) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.NewTimer(globalRefreshIAMInterval).C:
			// There is no pre-emptive loading, so we only
			// expire when the timer is hit
			logger.LogIf(ctx, s.expireAll(ctx, sys))
		}
	}
}
