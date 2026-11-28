package github

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sync"
	"unsafe"

	sdkplugin "github.com/oakwood-commons/scafctl-plugin-sdk/plugin"
	"github.com/oakwood-commons/scafctl-plugin-sdk/plugin/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxBackingStoreSecretNameLength = 255

// validateTestHostSecretName enforces both the host gRPC secret-name validation
// contract and the host backing-store character/length rules (1..255 bytes,
// leading ASCII alphanumeric, and only ASCII alphanumeric, '.', '_', or '-').
func validateTestHostSecretName(name string) error {
	if err := sdkplugin.ValidateHostSecretName(name); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if len(name) > maxBackingStoreSecretNameLength {
		return status.Errorf(codes.InvalidArgument, "secret name %q exceeds backing-store maximum length (%d bytes)", name, maxBackingStoreSecretNameLength)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 {
			if !isAlphaNum {
				return status.Errorf(codes.InvalidArgument, "secret name %q must start with an ASCII alphanumeric character", name)
			}
			continue
		}
		if !isAlphaNum && c != '.' && c != '_' && c != '-' {
			return status.Errorf(codes.InvalidArgument, "secret name %q contains invalid character %q", name, fmt.Sprintf("%c", c))
		}
	}
	return nil
}

// fakeHostService implements proto.HostServiceClient backed by an in-memory map
// while enforcing the real host secret-name and regex ListSecrets contracts.
type fakeHostService struct {
	mu               sync.Mutex
	secrets          map[string]string
	getSecretFunc    func(ctx context.Context, name string) error
	setSecretErr     error
	setSecretKeyErr  map[string]error
	setSecretFunc    func(ctx context.Context, name, value string) error
	deleteSecretFunc func(ctx context.Context, name string) error
	listSecretsFunc  func(ctx context.Context, pattern string) error
	promptFunc       func(ctx context.Context, req *proto.PromptAuthResponseRequest) (string, error)
}

func newFakeHostService() *fakeHostService {
	return &fakeHostService{secrets: make(map[string]string)}
}

// newFakeHostClient creates an sdkplugin.HostServiceClient backed by the fake.
func newFakeHostClient(fake *fakeHostService) *sdkplugin.HostServiceClient {
	hc := &sdkplugin.HostServiceClient{}
	// Inject the fake proto client into the unexported "client" field.
	field := reflect.ValueOf(hc).Elem().FieldByName("client")
	ptr := unsafe.Pointer(field.UnsafeAddr()) //nolint:gosec // intentional: injecting fake into unexported field for testing
	*(*proto.HostServiceClient)(ptr) = fake
	return hc
}

func (f *fakeHostService) GetSecret(ctx context.Context, in *proto.GetSecretRequest, _ ...grpc.CallOption) (*proto.GetSecretResponse, error) {
	if err := validateTestHostSecretName(in.Name); err != nil {
		return nil, err
	}

	f.mu.Lock()
	fn := f.getSecretFunc
	f.mu.Unlock()
	if fn != nil {
		if err := fn(ctx, in.Name); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.secrets[in.Name]
	return &proto.GetSecretResponse{Value: v, Found: ok}, nil
}

func (f *fakeHostService) SetSecret(ctx context.Context, in *proto.SetSecretRequest, _ ...grpc.CallOption) (*proto.SetSecretResponse, error) {
	if err := validateTestHostSecretName(in.Name); err != nil {
		return nil, err
	}

	f.mu.Lock()
	fn := f.setSecretFunc
	f.mu.Unlock()
	if fn != nil {
		if err := fn(ctx, in.Name, in.Value); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setSecretKeyErr != nil {
		if err, ok := f.setSecretKeyErr[in.Name]; ok && err != nil {
			return nil, err
		}
	}
	if f.setSecretErr != nil {
		return nil, f.setSecretErr
	}
	f.secrets[in.Name] = in.Value
	return &proto.SetSecretResponse{}, nil
}

func (f *fakeHostService) DeleteSecret(ctx context.Context, in *proto.DeleteSecretRequest, _ ...grpc.CallOption) (*proto.DeleteSecretResponse, error) {
	if err := validateTestHostSecretName(in.Name); err != nil {
		return nil, err
	}

	f.mu.Lock()
	fn := f.deleteSecretFunc
	f.mu.Unlock()
	if fn != nil {
		if err := fn(ctx, in.Name); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.secrets, in.Name)
	return &proto.DeleteSecretResponse{}, nil
}

func (f *fakeHostService) ListSecrets(ctx context.Context, in *proto.ListSecretsRequest, _ ...grpc.CallOption) (*proto.ListSecretsResponse, error) {
	if len(in.Pattern) > sdkplugin.MaxHostSecretPatternLength {
		return nil, status.Errorf(codes.InvalidArgument, "secret pattern exceeds maximum length (%d bytes)", sdkplugin.MaxHostSecretPatternLength)
	}
	var re *regexp.Regexp
	if in.Pattern != "" {
		var err error
		re, err = regexp.Compile(in.Pattern)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid secret pattern %q: %v", in.Pattern, err)
		}
	}

	f.mu.Lock()
	fn := f.listSecretsFunc
	f.mu.Unlock()
	if fn != nil {
		if err := fn(ctx, in.Pattern); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	var names []string
	for k := range f.secrets {
		if re == nil || re.MatchString(k) {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	return &proto.ListSecretsResponse{Names: names}, nil
}

func (f *fakeHostService) GetAuthIdentity(_ context.Context, _ *proto.GetAuthIdentityRequest, _ ...grpc.CallOption) (*proto.GetAuthIdentityResponse, error) {
	return &proto.GetAuthIdentityResponse{}, nil
}

func (f *fakeHostService) ListAuthHandlers(_ context.Context, _ *proto.ListAuthHandlersRequest, _ ...grpc.CallOption) (*proto.ListAuthHandlersResponse, error) {
	return &proto.ListAuthHandlersResponse{}, nil
}

func (f *fakeHostService) GetAuthToken(_ context.Context, _ *proto.GetAuthTokenRequest, _ ...grpc.CallOption) (*proto.GetAuthTokenResponse, error) {
	return &proto.GetAuthTokenResponse{}, nil
}

func (f *fakeHostService) GetAuthGroups(_ context.Context, _ *proto.GetAuthGroupsRequest, _ ...grpc.CallOption) (*proto.GetAuthGroupsResponse, error) {
	return &proto.GetAuthGroupsResponse{}, nil
}

func (f *fakeHostService) PromptAuthResponse(ctx context.Context, in *proto.PromptAuthResponseRequest, _ ...grpc.CallOption) (*proto.PromptAuthResponseResponse, error) {
	f.mu.Lock()
	fn := f.promptFunc
	f.mu.Unlock()
	if fn == nil {
		return nil, status.Error(codes.Unimplemented, "PromptAuthResponse not implemented")
	}
	v, err := fn(ctx, in)
	if err != nil {
		return nil, err
	}
	return &proto.PromptAuthResponseResponse{Value: v}, nil
}
