import type * as k8s from "@kubernetes/client-node";
import logger from "@/logging";
import type { K8sCapabilities } from "@/types";
import { createK8sClients, isK8sNotFoundError, loadKubeConfig } from "./shared";

// === Public API ===

export async function getK8sCapabilities(): Promise<K8sCapabilities> {
  try {
    const { kubeConfig, namespace } = loadKubeConfig();
    const clients = createK8sClients(kubeConfig, namespace);
    return getK8sCapabilitiesFromApi(clients.customObjectsApi);
  } catch (error) {
    logger.warn({ err: error }, "Failed to inspect Kubernetes capabilities");
    return unavailableCapabilities();
  }
}

export async function getK8sCapabilitiesFromApi(
  customObjectsApi: k8s.CustomObjectsApi,
): Promise<K8sCapabilities> {
  const ciliumNetworkPolicy =
    await hasCiliumNetworkPolicyResource(customObjectsApi);

  return {
    networkPolicy: {
      kubernetesNetworkPolicy: true,
      ciliumNetworkPolicy,
      provider: ciliumNetworkPolicy ? "cilium" : "kubernetes",
      supportsFqdn: ciliumNetworkPolicy,
      supportsHttpMethods: false,
      message: ciliumNetworkPolicy
        ? "CiliumNetworkPolicy API detected. Domain allowlists can be enforced by Cilium."
        : "CiliumNetworkPolicy API not detected. Domain allowlists require Cilium; Kubernetes NetworkPolicy only enforces IP/CIDR egress.",
    },
  };
}

// === Internal helpers ===

async function hasCiliumNetworkPolicyResource(
  customObjectsApi: k8s.CustomObjectsApi,
): Promise<boolean> {
  try {
    const resourceList = await customObjectsApi.getAPIResources({
      group: "cilium.io",
      version: "v2",
    });
    return (
      resourceList.resources?.some(
        (resource) => resource.name === "ciliumnetworkpolicies",
      ) ?? false
    );
  } catch (error) {
    if (isK8sNotFoundError(error)) {
      return false;
    }
    logger.warn(
      { err: error },
      "Failed to inspect Cilium Kubernetes API resources",
    );
    return false;
  }
}

function unavailableCapabilities(): K8sCapabilities {
  return {
    networkPolicy: {
      kubernetesNetworkPolicy: false,
      ciliumNetworkPolicy: false,
      provider: "none",
      supportsFqdn: false,
      supportsHttpMethods: false,
      message:
        "Kubernetes capabilities could not be inspected. Network policy enforcement is unavailable until Kubernetes access is configured.",
    },
  };
}
