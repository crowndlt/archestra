import type * as k8s from "@kubernetes/client-node";
import { sanitizeMetadataLabels } from "@/k8s/shared";
import type { EffectiveNetworkPolicy } from "@/types";

// === Public API ===

export function constructManagedNetworkPolicyName(
  deploymentName: string,
): string {
  return `mcp-egress-${deploymentName}`
    .toLowerCase()
    .replace(/\./g, "-")
    .slice(0, 253)
    .replace(/^[^a-z0-9]+/, "")
    .replace(/[^a-z0-9]+$/g, "");
}

export function shouldManageK8sNetworkPolicy(
  effectivePolicy?: EffectiveNetworkPolicy | null,
): boolean {
  return (
    effectivePolicy?.policy?.egressMode === "off" ||
    effectivePolicy?.policy?.egressMode === "restricted"
  );
}

export function buildManagedNetworkPolicy(params: {
  name: string;
  podSelectorLabels: Record<string, string>;
  effectivePolicy: EffectiveNetworkPolicy;
}): k8s.V1NetworkPolicy {
  const policy = params.effectivePolicy.policy;
  if (!policy) {
    throw new Error("Cannot build a managed NetworkPolicy without a policy");
  }

  const labels = sanitizeMetadataLabels({
    app: "mcp-server",
    "app.kubernetes.io/managed-by": "archestra",
    "archestra.io/resource": "mcp-network-policy",
    "archestra.io/network-policy-id": policy.id,
  });

  return {
    apiVersion: "networking.k8s.io/v1",
    kind: "NetworkPolicy",
    metadata: {
      name: params.name,
      labels,
      annotations: buildPolicyAnnotations(params.effectivePolicy),
    },
    spec: {
      podSelector: {
        matchLabels: params.podSelectorLabels,
      },
      policyTypes: ["Egress"],
      egress: buildEgressRules(policy.egressMode),
    },
  };
}

// === Internal helpers ===

function buildEgressRules(
  egressMode: NonNullable<EffectiveNetworkPolicy["policy"]>["egressMode"],
): k8s.V1NetworkPolicyEgressRule[] {
  if (egressMode === "off") {
    return [];
  }

  if (egressMode === "restricted") {
    return [buildDnsEgressRule()];
  }

  return [];
}

function buildDnsEgressRule(): k8s.V1NetworkPolicyEgressRule {
  return {
    to: [
      {
        namespaceSelector: {
          matchLabels: {
            "kubernetes.io/metadata.name": "kube-system",
          },
        },
        podSelector: {
          matchLabels: {
            "k8s-app": "kube-dns",
          },
        },
      },
    ],
    ports: [
      {
        protocol: "UDP",
        port: 53 as unknown as k8s.IntOrString,
      },
      {
        protocol: "TCP",
        port: 53 as unknown as k8s.IntOrString,
      },
    ],
  };
}

function buildPolicyAnnotations(
  effectivePolicy: EffectiveNetworkPolicy,
): Record<string, string> {
  const policy = effectivePolicy.policy;
  if (!policy) {
    return {};
  }

  return {
    "archestra.io/network-policy-source": effectivePolicy.source,
    "archestra.io/network-policy-id": policy.id,
    "archestra.io/network-policy-egress-mode": policy.egressMode,
    "archestra.io/network-policy-domain-preset": policy.domainPreset,
    "archestra.io/network-policy-allowed-domains":
      policy.allowedDomains.join(","),
    "archestra.io/network-policy-allowed-http-methods":
      policy.allowedHttpMethods,
    "archestra.io/network-policy-domain-enforcement":
      "not-supported-by-kubernetes-networkpolicy",
    "archestra.io/network-policy-http-method-enforcement":
      "not-supported-by-kubernetes-networkpolicy",
  };
}
