package cmd

import (
	"context"
	"regexp"

	"github.com/minio/minio/pkg/auth"
	iampolicy "github.com/minio/minio/pkg/iam/policy"
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
	engine PolicyEngine
}

func newOkeraIAMStore(engine PolicyEngine) (*okeraIAMStore, error) {
	store := &okeraIAMStore{
		engine: engine,
	}

	return store, nil
}

func (s *okeraIAMStore) IsAllowed(args iampolicy.Args) (bool, error) {
	return s.engine.IsAllowed(args)
}

func (s *okeraIAMStore) lock() {
	s.engine.Lock()
}

func (s *okeraIAMStore) unlock() {
	s.engine.Unlock()
}

func (s *okeraIAMStore) rlock() {
	s.engine.RLock()
}

func (s *okeraIAMStore) runlock() {
	s.engine.RUnlock()
}

func (s *okeraIAMStore) loadUser(user string, userType IAMUserType, m map[string]auth.Credentials) error {
	creds, err := s.engine.GetUserCredentials(user)
	if err != nil {
		return err
	}

	m[user] = creds
	return nil
}

func (s *okeraIAMStore) loadAll(ctx context.Context, sys *IAMSys) error {
	return s.engine.LoadAll(ctx, sys)
}

func (s *okeraIAMStore) watch(ctx context.Context, sys *IAMSys) {
	s.engine.Watch(ctx, sys)
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
