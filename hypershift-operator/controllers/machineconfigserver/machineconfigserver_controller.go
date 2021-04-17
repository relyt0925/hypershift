package machineconfigserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/blang/semver"
	"github.com/go-logr/logr"
	routev1 "github.com/openshift/api/route/v1"
	hyperv1 "github.com/openshift/hypershift/api/v1alpha1"
	"github.com/openshift/hypershift/control-plane-operator/releaseinfo"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	k8sutilspointer "k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	finalizer = "hypershift.openshift.io/finalizer"
)

var NoopReconcile controllerutil.MutateFn = func() error { return nil }

// MachineConfigServerReconciler reconciles machineConfigServer resources.
// For a given release it generates a machine config server serving ignition content,
// exposes the endpoint with a route and generates a user-data secret which references the endpoint
// TODO (alberto): Currently this controller only manages the resources associated to the mcs, i.e
// deployment and rbac resources. Something needs to generate the pki resources for each MCS resource
// which are currently statically generated by the HCP.
type MachineConfigServerReconciler struct {
	ctrlclient.Client
	recorder        record.EventRecorder
	Log             logr.Logger
	ReleaseProvider releaseinfo.Provider
}

func (r *MachineConfigServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	_, err := ctrl.NewControllerManagedBy(mgr).
		For(&hyperv1.MachineConfigServer{}).
		WithOptions(controller.Options{
			RateLimiter: workqueue.NewItemExponentialFailureRateLimiter(1*time.Second, 10*time.Second),
		}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Build(r)
	if err != nil {
		return fmt.Errorf("failed setting up with a controller manager %w", err)
	}

	r.recorder = mgr.GetEventRecorderFor("machine-config-server-controller")

	return nil
}

func (r *MachineConfigServerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.Log = ctrl.LoggerFrom(ctx)
	r.Log.Info("Reconciling")

	mcs := &hyperv1.MachineConfigServer{}
	err := r.Client.Get(ctx, req.NamespacedName, mcs)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	releaseImage, err := r.ReleaseProvider.Lookup(ctx, mcs.Spec.ReleaseImage)
	if err != nil {
		return ctrl.Result{}, err
	}
	r.Log = r.Log.WithValues("releaseImage", mcs.Spec.ReleaseImage, "version", releaseImage.Version())

	// Generate mcs manifests for the given release
	mcsServiceAccount := MachineConfigServerServiceAccount(mcs.Namespace, mcs.Name)

	mcsRoleBinding := MachineConfigServerRoleBinding(mcs.Namespace, mcs.Name)

	mcsService := MachineConfigServerService(mcs.Namespace, mcs.Name)

	mcsDeployment := MachineConfigServerDeployment(mcs.Namespace, mcs.Name)

	ignitionRoute := MachineConfigServerIgnitionRoute(mcs.Namespace, mcs.Name)

	userDataSecret := MachineConfigServerUserDataSecret(mcs)

	// Return early if deleted
	if !mcs.DeletionTimestamp.IsZero() {
		if err := r.Delete(ctx, mcsServiceAccount); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}

		if err := r.Delete(ctx, mcsRoleBinding); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}

		if err := r.Delete(ctx, mcsService); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}

		if err := r.Delete(ctx, mcsDeployment); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}

		switch mcs.Spec.IgnitionService.Type {
		case hyperv1.NodePort:
			r.Log.Info("No extra components to delete in node port strategy")
		case hyperv1.Route:
			r.Log.Info("Removing ignition route")
			if err := r.Delete(ctx, ignitionRoute); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		default:
			r.Log.Info("Unrecognized serviceType", "serviceType", mcs.Spec.IgnitionService.Type)
		}

		if err := r.Delete(ctx, userDataSecret); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}

		if controllerutil.ContainsFinalizer(mcs, finalizer) {
			controllerutil.RemoveFinalizer(mcs, finalizer)
			if err := r.Update(ctx, mcs); err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to remove finalizer from cluster: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure the machineConfigServer has a finalizer for cleanup
	if !controllerutil.ContainsFinalizer(mcs, finalizer) {
		controllerutil.AddFinalizer(mcs, finalizer)
		if err := r.Update(ctx, mcs); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer to hostedControlPlane: %w", err)
		}
	}

	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, mcsServiceAccount, NoopReconcile)
	if err != nil {
		return ctrl.Result{}, err
	}

	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, mcsRoleBinding, func() error {
		mcsRoleBinding.RoleRef = rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "edit",
		}
		mcsRoleBinding.Subjects = []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      mcsServiceAccount.Name,
				Namespace: mcsServiceAccount.Namespace,
			},
		}
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, mcsDeployment, func() error {
		return reconcileMCSDeployment(mcsDeployment, mcs, mcsServiceAccount, releaseImage.ComponentImages())
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	r.Log.Info("Reconciling MCS service")
	reconcileResult, err := r.reconcileMCSService(ctx, mcs, mcsService, ignitionRoute)
	if reconcileResult != nil {
		return *reconcileResult, err
	} else if err != nil {
		return ctrl.Result{}, err
	}

	r.Log.Info("Creating userdata secret")
	semversion, err := semver.Parse(releaseImage.Version())
	if err != nil {
		return ctrl.Result{}, nil
	}
	userDataSecret = MachineConfigServerUserDataSecret(mcs)
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, userDataSecret, func() error {
		// For now, only create and never update this secret
		if !userDataSecret.CreationTimestamp.IsZero() {
			return nil
		}
		disableTemplatingValue := []byte(base64.StdEncoding.EncodeToString([]byte("true")))
		var userDataValue []byte

		// Clear any version modifiers for this comparison
		semversion.Pre = nil
		semversion.Build = nil
		if semversion.GTE(semver.MustParse("4.6.0")) {
			userDataValue = []byte(fmt.Sprintf(`{"ignition":{"config":{"merge":[{"source":"http://%s:%d/config/master","verification":{}}]},"security":{},"timeouts":{},"version":"3.1.0"},"networkd":{},"passwd":{},"storage":{},"systemd":{}}`, mcs.Status.Host, mcs.Status.Port))
		} else {
			userDataValue = []byte(fmt.Sprintf(`{"ignition":{"config":{"append":[{"source":"http://%s:%d/config/master","verification":{}}]},"security":{},"timeouts":{},"version":"2.2.0"},"networkd":{},"passwd":{},"storage":{},"systemd":{}}`, mcs.Status.Host, mcs.Status.Port))
		}

		userDataSecret.Data = map[string][]byte{
			"disableTemplating": disableTemplatingValue,
			"value":             userDataValue,
		}
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	mcs.Status.Version = releaseImage.Version()
	if err := r.Status().Update(ctx, mcs); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *MachineConfigServerReconciler) reconcileMCSServiceNodePort(ctx context.Context, mcs *hyperv1.MachineConfigServer, mcsService *corev1.Service) (*ctrl.Result, error) {
	var serviceNodePort int32 = 0
	var machineConfigServerServiceData corev1.Service
	if mcs.Spec.IgnitionService.NodePort != nil && mcs.Spec.IgnitionService.NodePort.Port > 0 {
		serviceNodePort = mcs.Spec.IgnitionService.NodePort.Port
	}
	r.Log.Info("Checking for existing service", "serviceName", mcsService.Name, "namespace", mcsService.Namespace)
	if err := r.Client.Get(ctx, ctrlclient.ObjectKey{Namespace: mcsService.Namespace, Name: mcsService.Name}, &machineConfigServerServiceData); err != nil && !apierrors.IsNotFound(err) {
		return &ctrl.Result{}, err
	}
	if len(machineConfigServerServiceData.Spec.Ports) > 0 && machineConfigServerServiceData.Spec.Ports[0].NodePort > 0 {
		r.Log.Info("Existing node port exists for service. Preserving it", "nodePort", machineConfigServerServiceData.Spec.Ports[0].NodePort)
		serviceNodePort = machineConfigServerServiceData.Spec.Ports[0].NodePort
	}
	r.Log.Info("Creating MCS Service")
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, mcsService, func() error {
		mcsService.Spec.Ports = []corev1.ServicePort{
			{
				Name:       "http",
				Protocol:   corev1.ProtocolTCP,
				Port:       80,
				TargetPort: intstr.FromInt(8080),
			},
		}
		if serviceNodePort > 0 {
			mcsService.Spec.Ports[0].NodePort = serviceNodePort
		}
		mcsService.Spec.Selector = map[string]string{
			"app": fmt.Sprintf("machine-config-server-%s", mcs.Name),
		}
		mcsService.Spec.Type = corev1.ServiceTypeNodePort
		return nil
	})
	if err != nil {
		return &ctrl.Result{}, err
	}
	r.Log.Info("Retrieving MCS Service to get node port value")
	if err := r.Client.Get(ctx, ctrlclient.ObjectKey{Namespace: mcsService.Namespace, Name: mcsService.Name}, mcsService); err != nil {
		return &ctrl.Result{}, err
	}
	if !(mcsService.Spec.Ports[0].NodePort > 0) {
		r.Log.Info("Waiting for node port to populate")
		return &ctrl.Result{Requeue: true}, nil
	}
	mcs.Status.Host = mcs.Spec.IgnitionService.NodePort.Address
	mcs.Status.Port = mcsService.Spec.Ports[0].NodePort
	return nil, nil
}

func (r *MachineConfigServerReconciler) reconcileMCSServiceRoute(ctx context.Context, mcs *hyperv1.MachineConfigServer, mcsService *corev1.Service, ignitionRoute *routev1.Route) (*ctrl.Result, error) {
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, mcsService, func() error {
		mcsService.Spec.Ports = []corev1.ServicePort{
			{
				Name:       "http",
				Protocol:   corev1.ProtocolTCP,
				Port:       80,
				TargetPort: intstr.FromInt(8080),
				NodePort:   0,
			},
		}
		mcsService.Spec.Selector = map[string]string{
			"app": fmt.Sprintf("machine-config-server-%s", mcs.Name),
		}
		mcsService.Spec.Type = corev1.ServiceTypeClusterIP
		return nil
	})
	if err != nil {
		return &ctrl.Result{}, err
	}
	r.Log.Info("Creating ignition provider route")
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, ignitionRoute, func() error {
		ignitionRoute.Spec.To = routev1.RouteTargetReference{
			Kind: "Service",
			Name: fmt.Sprintf("machine-config-server-%s", mcs.Name),
		}
		return nil
	})
	if err != nil {
		return &ctrl.Result{}, err
	}
	if err := r.Get(ctx, ctrlclient.ObjectKeyFromObject(ignitionRoute), ignitionRoute); err != nil {
		return &ctrl.Result{}, err
	}
	if ignitionRoute.Spec.Host == "" {
		r.Log.Info("Waiting for ignition route to be available")
		return &ctrl.Result{Requeue: true}, nil
	}
	mcs.Status.Host = ignitionRoute.Spec.Host
	mcs.Status.Port = int32(80)
	return nil, nil
}

func (r *MachineConfigServerReconciler) reconcileMCSService(ctx context.Context, mcs *hyperv1.MachineConfigServer, mcsService *corev1.Service, ignitionRoute *routev1.Route) (*ctrl.Result, error) {
	serviceType := mcs.Spec.IgnitionService.Type
	switch serviceType {
	case hyperv1.NodePort:
		r.Log.Info("Reconciling MCS nodePort service")
		if mcs.Spec.IgnitionService.NodePort == nil {
			return &ctrl.Result{}, fmt.Errorf("nodePort metadata is not defined")
		}
		return r.reconcileMCSServiceNodePort(ctx, mcs, mcsService)
	case hyperv1.Route:
		r.Log.Info("Reconciling MCS route")
		return r.reconcileMCSServiceRoute(ctx, mcs, mcsService, ignitionRoute)
	default:
		return &ctrl.Result{}, fmt.Errorf("unrecognized mcs serviceType: %s", serviceType)
	}
}

func reconcileMCSDeployment(deployment *appsv1.Deployment, mcs *hyperv1.MachineConfigServer, sa *corev1.ServiceAccount, images map[string]string) error {
	bootstrapArgs := fmt.Sprintf(`
mkdir -p /mcc-manifests/bootstrap/manifests
mkdir -p /mcc-manifests/manifests
exec machine-config-operator bootstrap \
--root-ca=/assets/manifests/root-ca.crt \
--kube-ca=/assets/manifests/combined-ca.crt \
--machine-config-operator-image=%s \
--machine-config-oscontent-image=%s \
--infra-image=%s \
--keepalived-image=%s \
--coredns-image=%s \
--mdns-publisher-image=%s \
--haproxy-image=%s \
--baremetal-runtimecfg-image=%s \
--infra-config-file=/assets/manifests/cluster-infrastructure-02-config.yaml \
--network-config-file=/assets/manifests/cluster-network-02-config.yaml \
--proxy-config-file=/assets/manifests/cluster-proxy-01-config.yaml \
--config-file=/assets/manifests/install-config.yaml \
--dns-config-file=/assets/manifests/cluster-dns-02-config.yaml \
--dest-dir=/mcc-manifests \
--pull-secret=/assets/manifests/pull-secret.yaml

# Use our own version of configpools that swap master and workers
mv /mcc-manifests/bootstrap/manifests /mcc-manifests/bootstrap/manifests.tmp
mkdir /mcc-manifests/bootstrap/manifests
cp /mcc-manifests/bootstrap/manifests.tmp/* /mcc-manifests/bootstrap/manifests/
cp /assets/manifests/*.machineconfigpool.yaml /mcc-manifests/bootstrap/manifests/`,
		images["machine-config-operator"],
		images["machine-os-content"],
		images["pod"],
		images["keepalived-ipfailover"],
		images["coredns"],
		images["mdns-publisher"],
		images["haproxy-router"],
		images["baremetal-runtimecfg"],
	)

	customMachineConfigArg := `
cat <<"EOF" > "./copy-ignition-config.sh"
#!/bin/bash
name="${1}"
oc get cm ${name} -n "${NAMESPACE}" -o jsonpath='{ .data.data }' > "/mcc-manifests/bootstrap/manifests/${name/#ignition-config-//}.yaml"
EOF
chmod +x ./copy-ignition-config.sh
oc get cm -l ignition-config="true" -n "${NAMESPACE}" --no-headers | awk '{ print $1 }' | xargs -n1 ./copy-ignition-config.sh`

	deployment.Spec = appsv1.DeploymentSpec{
		Replicas: k8sutilspointer.Int32Ptr(1),
		Selector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"app": fmt.Sprintf("machine-config-server-%s", mcs.Name),
			},
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					"app": fmt.Sprintf("machine-config-server-%s", mcs.Name),
				},
			},
			Spec: corev1.PodSpec{
				ServiceAccountName:            sa.Name,
				TerminationGracePeriodSeconds: k8sutilspointer.Int64Ptr(10),
				Tolerations: []corev1.Toleration{
					{
						Key:      "multi-az-worker",
						Operator: "Equal",
						Value:    "true",
						Effect:   "NoSchedule",
					},
				},
				InitContainers: []corev1.Container{
					{
						Image: images["machine-config-operator"],
						Name:  "machine-config-operator-bootstrap",
						Command: []string{
							"/bin/bash",
						},
						Args: []string{
							"-c",
							bootstrapArgs,
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "mcc-manifests",
								MountPath: "/mcc-manifests",
							},
							{
								Name:      "config",
								MountPath: "/assets/manifests",
							},
						},
					},
					{
						Image:           images["cli"],
						ImagePullPolicy: corev1.PullIfNotPresent,
						Name:            "inject-custom-machine-configs",
						Env: []corev1.EnvVar{
							{
								Name: "NAMESPACE",
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "metadata.namespace",
									},
								},
							},
						},
						WorkingDir: "/tmp",
						Command: []string{
							"/usr/bin/bash",
						},
						Args: []string{
							"-c",
							customMachineConfigArg,
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "mcc-manifests",
								MountPath: "/mcc-manifests",
							},
						},
					},
					{
						Image:           images["machine-config-operator"],
						ImagePullPolicy: corev1.PullIfNotPresent,
						Name:            "machine-config-controller-bootstrap",
						Command: []string{
							"/usr/bin/machine-config-controller",
						},
						Args: []string{
							"bootstrap",
							"--manifest-dir=/mcc-manifests/bootstrap/manifests",
							"--pull-secret=/mcc-manifests/bootstrap/manifests/machineconfigcontroller-pull-secret",
							"--dest-dir=/mcs-manifests",
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "mcc-manifests",
								MountPath: "/mcc-manifests",
							},
							{
								Name:      "mcs-manifests",
								MountPath: "/mcs-manifests",
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Image:           images["machine-config-operator"],
						ImagePullPolicy: corev1.PullIfNotPresent,
						Name:            "machine-config-server",
						Command: []string{
							"/usr/bin/machine-config-server",
						},
						Args: []string{
							"bootstrap",
							"--bootstrap-kubeconfig=/etc/openshift/kubeconfig",
							"--secure-port=8443",
							"--insecure-port=8080",
						},
						Ports: []corev1.ContainerPort{
							{
								Name:          "http",
								ContainerPort: 8080,
								Protocol:      corev1.ProtocolTCP,
							},
							{
								Name:          "https",
								ContainerPort: 8443,
								Protocol:      corev1.ProtocolTCP,
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "kubeconfig",
								ReadOnly:  true,
								MountPath: "/etc/openshift",
							},
							{
								Name:      "mcs-manifests",
								MountPath: "/etc/mcs/bootstrap",
							},
							{
								Name:      "mcc-manifests",
								MountPath: "/etc/mcc/bootstrap",
							},
							{
								Name:      "mcs-tls",
								MountPath: "/etc/ssl/mcs",
							},
						},
					},
				},
				Volumes: []corev1.Volume{
					{
						Name: "kubeconfig",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: "machine-config-server-kubeconfig",
							},
						},
					},
					{
						Name: "mcs-tls",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: "machine-config-server",
							},
						},
					},
					{
						Name: "mcs-manifests",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					{
						Name: "mcc-manifests",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					{
						Name: "config",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "machine-config-server",
								},
							},
						},
					},
				},
			},
		},
	}
	return nil
}
