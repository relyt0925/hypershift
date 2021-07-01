// +build !ignore_autogenerated

/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *APIEndpoint) DeepCopyInto(out *APIEndpoint) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new APIEndpoint.
func (in *APIEndpoint) DeepCopy() *APIEndpoint {
	if in == nil {
		return nil
	}
	out := new(APIEndpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AWSCloudProviderConfig) DeepCopyInto(out *AWSCloudProviderConfig) {
	*out = *in
	if in.Subnet != nil {
		in, out := &in.Subnet, &out.Subnet
		*out = new(AWSResourceReference)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AWSCloudProviderConfig.
func (in *AWSCloudProviderConfig) DeepCopy() *AWSCloudProviderConfig {
	if in == nil {
		return nil
	}
	out := new(AWSCloudProviderConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AWSNodePoolPlatform) DeepCopyInto(out *AWSNodePoolPlatform) {
	*out = *in
	if in.Subnet != nil {
		in, out := &in.Subnet, &out.Subnet
		*out = new(AWSResourceReference)
		(*in).DeepCopyInto(*out)
	}
	if in.SecurityGroups != nil {
		in, out := &in.SecurityGroups, &out.SecurityGroups
		*out = make([]AWSResourceReference, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AWSNodePoolPlatform.
func (in *AWSNodePoolPlatform) DeepCopy() *AWSNodePoolPlatform {
	if in == nil {
		return nil
	}
	out := new(AWSNodePoolPlatform)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AWSPlatformSpec) DeepCopyInto(out *AWSPlatformSpec) {
	*out = *in
	if in.CloudProviderConfig != nil {
		in, out := &in.CloudProviderConfig, &out.CloudProviderConfig
		*out = new(AWSCloudProviderConfig)
		(*in).DeepCopyInto(*out)
	}
	if in.ServiceEndpoints != nil {
		in, out := &in.ServiceEndpoints, &out.ServiceEndpoints
		*out = make([]AWSServiceEndpoint, len(*in))
		copy(*out, *in)
	}
	if in.Roles != nil {
		in, out := &in.Roles, &out.Roles
		*out = make([]AWSRoleCredentials, len(*in))
		copy(*out, *in)
	}
	out.KubeCloudControllerCreds = in.KubeCloudControllerCreds
	out.NodePoolManagementCreds = in.NodePoolManagementCreds
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AWSPlatformSpec.
func (in *AWSPlatformSpec) DeepCopy() *AWSPlatformSpec {
	if in == nil {
		return nil
	}
	out := new(AWSPlatformSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AWSResourceReference) DeepCopyInto(out *AWSResourceReference) {
	*out = *in
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
	if in.ARN != nil {
		in, out := &in.ARN, &out.ARN
		*out = new(string)
		**out = **in
	}
	if in.Filters != nil {
		in, out := &in.Filters, &out.Filters
		*out = make([]Filter, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AWSResourceReference.
func (in *AWSResourceReference) DeepCopy() *AWSResourceReference {
	if in == nil {
		return nil
	}
	out := new(AWSResourceReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AWSRoleCredentials) DeepCopyInto(out *AWSRoleCredentials) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AWSRoleCredentials.
func (in *AWSRoleCredentials) DeepCopy() *AWSRoleCredentials {
	if in == nil {
		return nil
	}
	out := new(AWSRoleCredentials)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AWSServiceEndpoint) DeepCopyInto(out *AWSServiceEndpoint) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AWSServiceEndpoint.
func (in *AWSServiceEndpoint) DeepCopy() *AWSServiceEndpoint {
	if in == nil {
		return nil
	}
	out := new(AWSServiceEndpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterAutoscaling) DeepCopyInto(out *ClusterAutoscaling) {
	*out = *in
	if in.MaxNodesTotal != nil {
		in, out := &in.MaxNodesTotal, &out.MaxNodesTotal
		*out = new(int32)
		**out = **in
	}
	if in.MaxPodGracePeriod != nil {
		in, out := &in.MaxPodGracePeriod, &out.MaxPodGracePeriod
		*out = new(int32)
		**out = **in
	}
	if in.PodPriorityThreshold != nil {
		in, out := &in.PodPriorityThreshold, &out.PodPriorityThreshold
		*out = new(int32)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterAutoscaling.
func (in *ClusterAutoscaling) DeepCopy() *ClusterAutoscaling {
	if in == nil {
		return nil
	}
	out := new(ClusterAutoscaling)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterConfiguration) DeepCopyInto(out *ClusterConfiguration) {
	*out = *in
	if in.SecretRefs != nil {
		in, out := &in.SecretRefs, &out.SecretRefs
		*out = make([]v1.LocalObjectReference, len(*in))
		copy(*out, *in)
	}
	if in.ConfigMapRefs != nil {
		in, out := &in.ConfigMapRefs, &out.ConfigMapRefs
		*out = make([]v1.LocalObjectReference, len(*in))
		copy(*out, *in)
	}
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]runtime.RawExtension, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterConfiguration.
func (in *ClusterConfiguration) DeepCopy() *ClusterConfiguration {
	if in == nil {
		return nil
	}
	out := new(ClusterConfiguration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterNetworking) DeepCopyInto(out *ClusterNetworking) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterNetworking.
func (in *ClusterNetworking) DeepCopy() *ClusterNetworking {
	if in == nil {
		return nil
	}
	out := new(ClusterNetworking)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterVersionStatus) DeepCopyInto(out *ClusterVersionStatus) {
	*out = *in
	out.Desired = in.Desired
	if in.History != nil {
		in, out := &in.History, &out.History
		*out = make([]configv1.UpdateHistory, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterVersionStatus.
func (in *ClusterVersionStatus) DeepCopy() *ClusterVersionStatus {
	if in == nil {
		return nil
	}
	out := new(ClusterVersionStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DNSSpec) DeepCopyInto(out *DNSSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DNSSpec.
func (in *DNSSpec) DeepCopy() *DNSSpec {
	if in == nil {
		return nil
	}
	out := new(DNSSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EtcdSpec) DeepCopyInto(out *EtcdSpec) {
	*out = *in
	if in.Managed != nil {
		in, out := &in.Managed, &out.Managed
		*out = new(ManagedEtcdSpec)
		**out = **in
	}
	if in.Unmanaged != nil {
		in, out := &in.Unmanaged, &out.Unmanaged
		*out = new(UnmanagedEtcdSpec)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EtcdSpec.
func (in *EtcdSpec) DeepCopy() *EtcdSpec {
	if in == nil {
		return nil
	}
	out := new(EtcdSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EtcdTLSConfig) DeepCopyInto(out *EtcdTLSConfig) {
	*out = *in
	out.ClientSecret = in.ClientSecret
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EtcdTLSConfig.
func (in *EtcdTLSConfig) DeepCopy() *EtcdTLSConfig {
	if in == nil {
		return nil
	}
	out := new(EtcdTLSConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Filter) DeepCopyInto(out *Filter) {
	*out = *in
	if in.Values != nil {
		in, out := &in.Values, &out.Values
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Filter.
func (in *Filter) DeepCopy() *Filter {
	if in == nil {
		return nil
	}
	out := new(Filter)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HostedCluster) DeepCopyInto(out *HostedCluster) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HostedCluster.
func (in *HostedCluster) DeepCopy() *HostedCluster {
	if in == nil {
		return nil
	}
	out := new(HostedCluster)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *HostedCluster) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HostedClusterList) DeepCopyInto(out *HostedClusterList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]HostedCluster, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HostedClusterList.
func (in *HostedClusterList) DeepCopy() *HostedClusterList {
	if in == nil {
		return nil
	}
	out := new(HostedClusterList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *HostedClusterList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HostedClusterSpec) DeepCopyInto(out *HostedClusterSpec) {
	*out = *in
	out.Release = in.Release
	out.PullSecret = in.PullSecret
	if in.AuditWebhook != nil {
		in, out := &in.AuditWebhook, &out.AuditWebhook
		*out = new(v1.LocalObjectReference)
		**out = **in
	}
	out.SigningKey = in.SigningKey
	out.SSHKey = in.SSHKey
	out.Networking = in.Networking
	in.Autoscaling.DeepCopyInto(&out.Autoscaling)
	in.Platform.DeepCopyInto(&out.Platform)
	out.DNS = in.DNS
	if in.Services != nil {
		in, out := &in.Services, &out.Services
		*out = make([]ServicePublishingStrategyMapping, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	in.Etcd.DeepCopyInto(&out.Etcd)
	in.Configuration.DeepCopyInto(&out.Configuration)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HostedClusterSpec.
func (in *HostedClusterSpec) DeepCopy() *HostedClusterSpec {
	if in == nil {
		return nil
	}
	out := new(HostedClusterSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HostedClusterStatus) DeepCopyInto(out *HostedClusterStatus) {
	*out = *in
	if in.Version != nil {
		in, out := &in.Version, &out.Version
		*out = new(ClusterVersionStatus)
		(*in).DeepCopyInto(*out)
	}
	if in.KubeConfig != nil {
		in, out := &in.KubeConfig, &out.KubeConfig
		*out = new(v1.LocalObjectReference)
		**out = **in
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HostedClusterStatus.
func (in *HostedClusterStatus) DeepCopy() *HostedClusterStatus {
	if in == nil {
		return nil
	}
	out := new(HostedClusterStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HostedControlPlane) DeepCopyInto(out *HostedControlPlane) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HostedControlPlane.
func (in *HostedControlPlane) DeepCopy() *HostedControlPlane {
	if in == nil {
		return nil
	}
	out := new(HostedControlPlane)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *HostedControlPlane) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HostedControlPlaneList) DeepCopyInto(out *HostedControlPlaneList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]HostedControlPlane, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HostedControlPlaneList.
func (in *HostedControlPlaneList) DeepCopy() *HostedControlPlaneList {
	if in == nil {
		return nil
	}
	out := new(HostedControlPlaneList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *HostedControlPlaneList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HostedControlPlaneSpec) DeepCopyInto(out *HostedControlPlaneSpec) {
	*out = *in
	out.PullSecret = in.PullSecret
	out.SigningKey = in.SigningKey
	out.SSHKey = in.SSHKey
	in.Platform.DeepCopyInto(&out.Platform)
	out.DNS = in.DNS
	if in.KubeConfig != nil {
		in, out := &in.KubeConfig, &out.KubeConfig
		*out = new(KubeconfigSecretRef)
		**out = **in
	}
	if in.Services != nil {
		in, out := &in.Services, &out.Services
		*out = make([]ServicePublishingStrategyMapping, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.AuditWebhook != nil {
		in, out := &in.AuditWebhook, &out.AuditWebhook
		*out = new(v1.LocalObjectReference)
		**out = **in
	}
	in.Etcd.DeepCopyInto(&out.Etcd)
	in.Configuration.DeepCopyInto(&out.Configuration)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HostedControlPlaneSpec.
func (in *HostedControlPlaneSpec) DeepCopy() *HostedControlPlaneSpec {
	if in == nil {
		return nil
	}
	out := new(HostedControlPlaneSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *HostedControlPlaneStatus) DeepCopyInto(out *HostedControlPlaneStatus) {
	*out = *in
	if in.ExternalManagedControlPlane != nil {
		in, out := &in.ExternalManagedControlPlane, &out.ExternalManagedControlPlane
		*out = new(bool)
		**out = **in
	}
	out.ControlPlaneEndpoint = in.ControlPlaneEndpoint
	if in.LastReleaseImageTransitionTime != nil {
		in, out := &in.LastReleaseImageTransitionTime, &out.LastReleaseImageTransitionTime
		*out = (*in).DeepCopy()
	}
	if in.KubeConfig != nil {
		in, out := &in.KubeConfig, &out.KubeConfig
		*out = new(KubeconfigSecretRef)
		**out = **in
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new HostedControlPlaneStatus.
func (in *HostedControlPlaneStatus) DeepCopy() *HostedControlPlaneStatus {
	if in == nil {
		return nil
	}
	out := new(HostedControlPlaneStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *InPlaceUpgrade) DeepCopyInto(out *InPlaceUpgrade) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new InPlaceUpgrade.
func (in *InPlaceUpgrade) DeepCopy() *InPlaceUpgrade {
	if in == nil {
		return nil
	}
	out := new(InPlaceUpgrade)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *KubeconfigSecretRef) DeepCopyInto(out *KubeconfigSecretRef) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new KubeconfigSecretRef.
func (in *KubeconfigSecretRef) DeepCopy() *KubeconfigSecretRef {
	if in == nil {
		return nil
	}
	out := new(KubeconfigSecretRef)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ManagedEtcdSpec) DeepCopyInto(out *ManagedEtcdSpec) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ManagedEtcdSpec.
func (in *ManagedEtcdSpec) DeepCopy() *ManagedEtcdSpec {
	if in == nil {
		return nil
	}
	out := new(ManagedEtcdSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodePool) DeepCopyInto(out *NodePool) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodePool.
func (in *NodePool) DeepCopy() *NodePool {
	if in == nil {
		return nil
	}
	out := new(NodePool)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NodePool) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodePoolAutoScaling) DeepCopyInto(out *NodePoolAutoScaling) {
	*out = *in
	if in.Min != nil {
		in, out := &in.Min, &out.Min
		*out = new(int)
		**out = **in
	}
	if in.Max != nil {
		in, out := &in.Max, &out.Max
		*out = new(int)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodePoolAutoScaling.
func (in *NodePoolAutoScaling) DeepCopy() *NodePoolAutoScaling {
	if in == nil {
		return nil
	}
	out := new(NodePoolAutoScaling)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodePoolList) DeepCopyInto(out *NodePoolList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NodePool, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodePoolList.
func (in *NodePoolList) DeepCopy() *NodePoolList {
	if in == nil {
		return nil
	}
	out := new(NodePoolList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NodePoolList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodePoolManagement) DeepCopyInto(out *NodePoolManagement) {
	*out = *in
	if in.Replace != nil {
		in, out := &in.Replace, &out.Replace
		*out = new(ReplaceUpgrade)
		(*in).DeepCopyInto(*out)
	}
	if in.InPlace != nil {
		in, out := &in.InPlace, &out.InPlace
		*out = new(InPlaceUpgrade)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodePoolManagement.
func (in *NodePoolManagement) DeepCopy() *NodePoolManagement {
	if in == nil {
		return nil
	}
	out := new(NodePoolManagement)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodePoolPlatform) DeepCopyInto(out *NodePoolPlatform) {
	*out = *in
	if in.AWS != nil {
		in, out := &in.AWS, &out.AWS
		*out = new(AWSNodePoolPlatform)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodePoolPlatform.
func (in *NodePoolPlatform) DeepCopy() *NodePoolPlatform {
	if in == nil {
		return nil
	}
	out := new(NodePoolPlatform)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodePoolSpec) DeepCopyInto(out *NodePoolSpec) {
	*out = *in
	if in.NodeCount != nil {
		in, out := &in.NodeCount, &out.NodeCount
		*out = new(int32)
		**out = **in
	}
	if in.Config != nil {
		in, out := &in.Config, &out.Config
		*out = make([]v1.LocalObjectReference, len(*in))
		copy(*out, *in)
	}
	in.Management.DeepCopyInto(&out.Management)
	if in.AutoScaling != nil {
		in, out := &in.AutoScaling, &out.AutoScaling
		*out = new(NodePoolAutoScaling)
		(*in).DeepCopyInto(*out)
	}
	in.Platform.DeepCopyInto(&out.Platform)
	out.Release = in.Release
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodePoolSpec.
func (in *NodePoolSpec) DeepCopy() *NodePoolSpec {
	if in == nil {
		return nil
	}
	out := new(NodePoolSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodePoolStatus) DeepCopyInto(out *NodePoolStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]metav1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodePoolStatus.
func (in *NodePoolStatus) DeepCopy() *NodePoolStatus {
	if in == nil {
		return nil
	}
	out := new(NodePoolStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NodePortPublishingStrategy) DeepCopyInto(out *NodePortPublishingStrategy) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NodePortPublishingStrategy.
func (in *NodePortPublishingStrategy) DeepCopy() *NodePortPublishingStrategy {
	if in == nil {
		return nil
	}
	out := new(NodePortPublishingStrategy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PlatformSpec) DeepCopyInto(out *PlatformSpec) {
	*out = *in
	if in.AWS != nil {
		in, out := &in.AWS, &out.AWS
		*out = new(AWSPlatformSpec)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PlatformSpec.
func (in *PlatformSpec) DeepCopy() *PlatformSpec {
	if in == nil {
		return nil
	}
	out := new(PlatformSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Release) DeepCopyInto(out *Release) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Release.
func (in *Release) DeepCopy() *Release {
	if in == nil {
		return nil
	}
	out := new(Release)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ReplaceUpgrade) DeepCopyInto(out *ReplaceUpgrade) {
	*out = *in
	if in.RollingUpdate != nil {
		in, out := &in.RollingUpdate, &out.RollingUpdate
		*out = new(RollingUpdate)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ReplaceUpgrade.
func (in *ReplaceUpgrade) DeepCopy() *ReplaceUpgrade {
	if in == nil {
		return nil
	}
	out := new(ReplaceUpgrade)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RollingUpdate) DeepCopyInto(out *RollingUpdate) {
	*out = *in
	if in.MaxUnavailable != nil {
		in, out := &in.MaxUnavailable, &out.MaxUnavailable
		*out = new(intstr.IntOrString)
		**out = **in
	}
	if in.MaxSurge != nil {
		in, out := &in.MaxSurge, &out.MaxSurge
		*out = new(intstr.IntOrString)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RollingUpdate.
func (in *RollingUpdate) DeepCopy() *RollingUpdate {
	if in == nil {
		return nil
	}
	out := new(RollingUpdate)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServicePublishingStrategy) DeepCopyInto(out *ServicePublishingStrategy) {
	*out = *in
	if in.NodePort != nil {
		in, out := &in.NodePort, &out.NodePort
		*out = new(NodePortPublishingStrategy)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServicePublishingStrategy.
func (in *ServicePublishingStrategy) DeepCopy() *ServicePublishingStrategy {
	if in == nil {
		return nil
	}
	out := new(ServicePublishingStrategy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ServicePublishingStrategyMapping) DeepCopyInto(out *ServicePublishingStrategyMapping) {
	*out = *in
	in.ServicePublishingStrategy.DeepCopyInto(&out.ServicePublishingStrategy)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ServicePublishingStrategyMapping.
func (in *ServicePublishingStrategyMapping) DeepCopy() *ServicePublishingStrategyMapping {
	if in == nil {
		return nil
	}
	out := new(ServicePublishingStrategyMapping)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UnmanagedEtcdSpec) DeepCopyInto(out *UnmanagedEtcdSpec) {
	*out = *in
	out.TLS = in.TLS
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UnmanagedEtcdSpec.
func (in *UnmanagedEtcdSpec) DeepCopy() *UnmanagedEtcdSpec {
	if in == nil {
		return nil
	}
	out := new(UnmanagedEtcdSpec)
	in.DeepCopyInto(out)
	return out
}
